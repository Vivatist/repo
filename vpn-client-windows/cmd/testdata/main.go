package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/novavpn/vpn-client-windows/internal/crypto"
	"github.com/novavpn/vpn-client-windows/internal/protocol"
)

// buildICMPEchoRequest создаёт raw IP + ICMP Echo Request пакет.
func buildICMPEchoRequest(srcIP, dstIP net.IP, id, seq uint16) []byte {
	// ICMP Echo Request
	icmp := make([]byte, 8)
	icmp[0] = 8 // Type: Echo Request
	icmp[1] = 0 // Code
	// Checksum placeholder
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	// ICMP checksum
	csum := checksum(icmp)
	binary.BigEndian.PutUint16(icmp[2:4], csum)

	// IPv4 header (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45 // Version 4, IHL 5
	ip[1] = 0    // TOS
	totalLen := uint16(20 + len(icmp))
	binary.BigEndian.PutUint16(ip[2:4], totalLen)
	binary.BigEndian.PutUint16(ip[4:6], id) // ID
	ip[6] = 0x40                             // Don't fragment
	ip[7] = 0
	ip[8] = 64   // TTL
	ip[9] = 1    // Protocol: ICMP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	// IP header checksum
	ipCsum := checksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], ipCsum)

	pkt := append(ip, icmp...)
	return pkt
}

func checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func main() {
	serverAddr := "212.118.43.43:51820"
	pskHex := "95c6646b379581a2b51b5926747e36a4f254449246e33a7d1731dfb68f39fe46"
	email := "test@novavpn.com"
	password := "TestPass123!"

	fmt.Println("=== NovaVPN Data Path Test ===")

	psk, err := crypto.DecodePSK(pskHex)
	if err != nil {
		log.Fatalf("PSK: %v", err)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("KeyPair: %v", err)
	}

	// --- Handshake ---
	credentials := protocol.MarshalCredentials(email, password)
	credsNonce, credsCiphertext, err := crypto.Encrypt(psk, credentials, nil)
	if err != nil {
		log.Fatalf("Encrypt creds: %v", err)
	}
	encCreds := make([]byte, 12+len(credsCiphertext))
	copy(encCreds[:12], credsNonce[:])
	copy(encCreds[12:], credsCiphertext)

	init := &protocol.HandshakeInit{
		ClientPublicKey:      kp.PublicKey,
		Timestamp:            uint64(time.Now().Unix()),
		EncryptedCredentials: encCreds,
	}
	hmacData := make([]byte, 32+8+len(encCreds))
	copy(hmacData[:32], init.ClientPublicKey[:])
	binary.BigEndian.PutUint64(hmacData[32:40], init.Timestamp)
	copy(hmacData[40:], init.EncryptedCredentials)
	init.HMAC = crypto.ComputeHMAC(psk, hmacData)

	initPayload := protocol.MarshalHandshakeInit(init)
	var zeroNonce [protocol.NonceSize]byte
	initPkt := protocol.NewPacket(protocol.PacketHandshakeInit, 0, 0, zeroNonce, initPayload)
	initData, _ := initPkt.Marshal()

	addr, _ := net.ResolveUDPAddr("udp", serverAddr)
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("UDP: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conn.Write(initData)
	fmt.Println("[OK] HandshakeInit sent")

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Recv HandshakeResp: %v", err)
	}
	respPkt, _ := protocol.Unmarshal(buf[:n])
	if respPkt.Header.Type == protocol.PacketError {
		log.Fatal("[ERROR] Server rejected")
	}

	var serverPubKey [32]byte
	copy(serverPubKey[:], respPkt.Payload[:32])
	sharedSecret, _ := crypto.ComputeSharedSecret(kp.PrivateKey, serverPubKey)
	sessionKeys, _ := crypto.DeriveSessionKeys(sharedSecret, psk, false)
	decrypted, err := crypto.Decrypt(sessionKeys.RecvKey, respPkt.Nonce, respPkt.Payload[32:], nil)
	if err != nil {
		log.Fatalf("Decrypt HandshakeResp: %v", err)
	}
	resp, _ := protocol.UnmarshalHandshakeResp(decrypted)
	fmt.Printf("[OK] Handshake done: Session=%d, IP=%s\n", resp.SessionID, resp.AssignedIP)

	// HandshakeComplete
	confirmData := []byte(fmt.Sprintf("novavpn-confirm-%d", resp.SessionID))
	confirmHMAC := crypto.ComputeHMAC(sessionKeys.HMACKey, confirmData)
	complete := &protocol.HandshakeComplete{ConfirmHMAC: confirmHMAC}
	completePayload := protocol.MarshalHandshakeComplete(complete)
	completeNonce, completeCT, _ := crypto.Encrypt(sessionKeys.SendKey, completePayload, nil)
	completePkt := protocol.NewPacket(protocol.PacketHandshakeComplete, resp.SessionID, 0, completeNonce, completeCT)
	completeData, _ := completePkt.Marshal()
	conn.Write(completeData)
	fmt.Println("[OK] HandshakeComplete sent")

	time.Sleep(500 * time.Millisecond)

	// --- Data Test: Send ICMP ping 10.8.0.2 → 8.8.8.8 ---
	icmpPacket := buildICMPEchoRequest(resp.AssignedIP.To4(), net.ParseIP("8.8.8.8").To4(), 1234, 1)
	fmt.Printf("[DATA] Sending ICMP echo request to 8.8.8.8 (%d bytes IP packet)\n", len(icmpPacket))

	seq := uint32(2)
	header := protocol.PacketHeader{
		Magic:      protocol.ProtocolMagic,
		Version:    protocol.ProtocolVersion,
		Type:       protocol.PacketData,
		SessionID:  resp.SessionID,
		SequenceNo: seq,
		PayloadLen: uint16(len(icmpPacket)), // plaintext length для AAD
	}
	aad := header.MarshalHeader()

	dataNonce, dataCT, err := crypto.Encrypt(sessionKeys.SendKey, icmpPacket, aad)
	if err != nil {
		log.Fatalf("Encrypt data: %v", err)
	}

	// Используем оригинальный header (PayloadLen = plaintext length) для консистентности AAD
	dataPkt := &protocol.Packet{
		Header:  header,
		Nonce:   dataNonce,
		Payload: dataCT,
	}
	dataBytes, _ := dataPkt.Marshal()
	conn.Write(dataBytes)
	fmt.Printf("[DATA] Sent encrypted data packet (%d bytes wire)\n", len(dataBytes))

	// Wait for ICMP reply (Data packet from server)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("[DATA] No response from server: %v\n", err)
		fmt.Println("[FAIL] Data path NOT working")
	} else {
		replyPkt, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			fmt.Printf("[DATA] Bad response: %v\n", err)
		} else {
			fmt.Printf("[DATA] Received packet type: %s (%d bytes)\n", replyPkt.Header.Type, n)
			if replyPkt.Header.Type == protocol.PacketData {
				// Decrypt
				replyAAD := replyPkt.Header.MarshalHeader()
				plaintext, err := crypto.Decrypt(sessionKeys.RecvKey, replyPkt.Nonce, replyPkt.Payload, replyAAD)
				if err != nil {
					fmt.Printf("[DATA] Decrypt reply FAILED: %v\n", err)
					fmt.Printf("[DATA] Header PayloadLen=%d, Payload len=%d, AuthTagSize=%d\n",
						replyPkt.Header.PayloadLen, len(replyPkt.Payload), crypto.AuthTagSize)
					fmt.Println("[FAIL] AAD mismatch still present!")
				} else {
					fmt.Printf("[DATA] Decrypted reply: %d bytes IP packet\n", len(plaintext))
					if len(plaintext) >= 20 {
						proto := plaintext[9]
						srcIP := net.IPv4(plaintext[12], plaintext[13], plaintext[14], plaintext[15])
						dstIP := net.IPv4(plaintext[16], plaintext[17], plaintext[18], plaintext[19])
						fmt.Printf("[DATA] IP: %s -> %s, proto=%d\n", srcIP, dstIP, proto)
					}
					fmt.Println("\n=== DATA PATH WORKING! ===")
				}
			} else if replyPkt.Header.Type == protocol.PacketKeepalive {
				fmt.Println("[DATA] Got keepalive instead of data reply - data might not have reached TUN")
			}
		}
	}

	// Disconnect
	disconnectPkt := protocol.NewDisconnectPacket(resp.SessionID, 99)
	disconnectData, _ := disconnectPkt.Marshal()
	conn.Write(disconnectData)
	fmt.Println("[OK] Disconnect sent")
	fmt.Println("=== TEST COMPLETE ===")
}
