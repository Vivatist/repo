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

func main() {
	serverAddr := "212.118.43.43:51820"
	pskHex := "95c6646b379581a2b51b5926747e36a4f254449246e33a7d1731dfb68f39fe46"
	email := "test@novavpn.com"
	password := "TestPass123!"

	fmt.Println("=== NovaVPN Protocol Test ===")
	fmt.Printf("Server: %s\n", serverAddr)
	fmt.Printf("Email:  %s\n", email)

	// Decode PSK
	psk, err := crypto.DecodePSK(pskHex)
	if err != nil {
		log.Fatalf("Failed to decode PSK: %v", err)
	}
	fmt.Println("[OK] PSK decoded")

	// Generate ephemeral key pair
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Println("[OK] Ephemeral key pair generated")

	// Marshal and encrypt credentials
	credentials := protocol.MarshalCredentials(email, password)
	fmt.Printf("[OK] Credentials marshaled (%d bytes)\n", len(credentials))

	credsNonce, credsCiphertext, err := crypto.Encrypt(psk, credentials, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt credentials: %v", err)
	}
	// EncryptedCredentials = nonce(12) + ciphertext
	encryptedCreds := make([]byte, len(credsNonce)+len(credsCiphertext))
	copy(encryptedCreds[:12], credsNonce[:])
	copy(encryptedCreds[12:], credsCiphertext)
	fmt.Printf("[OK] Credentials encrypted (%d bytes)\n", len(encryptedCreds))

	// Build HandshakeInit
	init := &protocol.HandshakeInit{
		ClientPublicKey:      kp.PublicKey,
		Timestamp:            uint64(time.Now().Unix()),
		EncryptedCredentials: encryptedCreds,
	}

	// Compute HMAC over init data (same as server verification)
	hmacData := make([]byte, 32+8+len(encryptedCreds))
	copy(hmacData[:32], init.ClientPublicKey[:])
	binary.BigEndian.PutUint64(hmacData[32:40], init.Timestamp)
	copy(hmacData[40:], init.EncryptedCredentials)
	init.HMAC = crypto.ComputeHMAC(psk, hmacData)

	fmt.Println("[OK] HandshakeInit built with HMAC")

	// Marshal HandshakeInit
	initPayload := protocol.MarshalHandshakeInit(init)
	fmt.Printf("[OK] HandshakeInit marshaled (%d bytes)\n", len(initPayload))

	// Create packet (HandshakeInit has no encryption, so zero nonce)
	var zeroNonce [protocol.NonceSize]byte
	initPacket := protocol.NewPacket(protocol.PacketHandshakeInit, 0, 0, zeroNonce, initPayload)
	initData, err := initPacket.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal packet: %v", err)
	}
	fmt.Printf("[OK] Packet marshaled (%d bytes total)\n", len(initData))

	// Connect UDP
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	fmt.Println("[OK] UDP connection established")

	// Send HandshakeInit
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Write(initData)
	if err != nil {
		log.Fatalf("Failed to send HandshakeInit: %v", err)
	}
	fmt.Printf("[OK] HandshakeInit sent (%d bytes)\n", n)

	// Receive HandshakeResp
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65536)
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to receive HandshakeResp: %v", err)
	}
	fmt.Printf("[OK] Received response (%d bytes)\n", n)

	// Unmarshal packet
	respPacket, err := protocol.Unmarshal(buf[:n])
	if err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}
	fmt.Printf("[OK] Response packet type: 0x%02X (%s), session: %d\n",
		respPacket.Header.Type, respPacket.Header.Type, respPacket.Header.SessionID)

	if respPacket.Header.Type == protocol.PacketError {
		fmt.Printf("[ERROR] Server returned error: %s\n", string(respPacket.Payload))
		return
	}

	if respPacket.Header.Type != protocol.PacketHandshakeResp {
		log.Fatalf("Unexpected packet type: 0x%02X", respPacket.Header.Type)
	}

	// Payload format: ServerPublicKey(32B cleartext) + encrypted(MarshalHandshakeResp)
	if len(respPacket.Payload) < 32 {
		log.Fatalf("HandshakeResp payload too short: %d", len(respPacket.Payload))
	}

	var serverPubKey [32]byte
	copy(serverPubKey[:], respPacket.Payload[:32])
	encryptedResp := respPacket.Payload[32:]
	fmt.Printf("[OK] Server public key extracted (first 4 bytes: %02x%02x%02x%02x)\n",
		serverPubKey[0], serverPubKey[1], serverPubKey[2], serverPubKey[3])

	// ECDH -> shared secret -> session keys
	sharedSecret, err := crypto.ComputeSharedSecret(kp.PrivateKey, serverPubKey)
	if err != nil {
		log.Fatalf("Failed to compute shared secret: %v", err)
	}
	fmt.Println("[OK] Shared secret computed")

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, psk, false)
	if err != nil {
		log.Fatalf("Failed to derive session keys: %v", err)
	}
	fmt.Println("[OK] Session keys derived")

	// Decrypt the rest of HandshakeResp - nonce is in packet header
	decrypted, err := crypto.Decrypt(sessionKeys.RecvKey, respPacket.Nonce, encryptedResp, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt HandshakeResp: %v", err)
	}
	fmt.Printf("[OK] HandshakeResp decrypted (%d bytes)\n", len(decrypted))

	// Unmarshal HandshakeResp
	resp, err := protocol.UnmarshalHandshakeResp(decrypted)
	if err != nil {
		log.Fatalf("Failed to unmarshal HandshakeResp: %v", err)
	}

	fmt.Printf("[OK] Session ID: %d\n", resp.SessionID)
	fmt.Printf("[OK] Assigned IP: %s\n", resp.AssignedIP.String())
	fmt.Printf("[OK] Subnet: /%d\n", resp.SubnetMask)
	fmt.Printf("[OK] DNS1: %s\n", resp.DNS1.String())
	fmt.Printf("[OK] DNS2: %s\n", resp.DNS2.String())
	fmt.Printf("[OK] MTU: %d\n", resp.MTU)

	// Verify server HMAC (on first 51 bytes of marshaled resp = everything before ServerHMAC)
	respDataForHMAC := decrypted[:51]
	if !crypto.VerifyHMAC(sessionKeys.HMACKey, respDataForHMAC, resp.ServerHMAC) {
		log.Fatal("Server HMAC verification FAILED!")
	}
	fmt.Println("[OK] Server HMAC verified")

	// === Send HandshakeComplete ===
	// ConfirmHMAC = HMAC(HMACKey, "novavpn-confirm-<sessionID>")
	confirmData := []byte(fmt.Sprintf("novavpn-confirm-%d", resp.SessionID))
	confirmHMAC := crypto.ComputeHMAC(sessionKeys.HMACKey, confirmData)

	complete := &protocol.HandshakeComplete{ConfirmHMAC: confirmHMAC}
	completePayload := protocol.MarshalHandshakeComplete(complete)

	// Encrypt HandshakeComplete with SendKey
	completeNonce, completeCiphertext, err := crypto.Encrypt(sessionKeys.SendKey, completePayload, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt HandshakeComplete: %v", err)
	}

	completePacket := protocol.NewPacket(protocol.PacketHandshakeComplete, resp.SessionID, 0, completeNonce, completeCiphertext)
	completeData, err := completePacket.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal HandshakeComplete: %v", err)
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Write(completeData)
	if err != nil {
		log.Fatalf("Failed to send HandshakeComplete: %v", err)
	}
	fmt.Printf("[OK] HandshakeComplete sent (%d bytes)\n", n)

	fmt.Println("\n=== HANDSHAKE SUCCESSFUL! ===")
	fmt.Printf("Session: %d, IP: %s/%d, MTU: %d\n", resp.SessionID, resp.AssignedIP, resp.SubnetMask, resp.MTU)

	// Keep alive for a few seconds to confirm session is active
	time.Sleep(2 * time.Second)

	// Send a keepalive to verify the session works
	keepalivePacket := protocol.NewKeepalivePacket(resp.SessionID, 1)
	keepaliveData, err := keepalivePacket.Marshal()
	if err == nil {
		conn.Write(keepaliveData)
		fmt.Println("[OK] Keepalive sent")
	}

	time.Sleep(1 * time.Second)

	// Send Disconnect
	disconnectPacket := protocol.NewDisconnectPacket(resp.SessionID, 1)
	disconnectData, err := disconnectPacket.Marshal()
	if err == nil {
		conn.Write(disconnectData)
		fmt.Println("[OK] Disconnect sent")
	}

	fmt.Println("\n=== TEST COMPLETE ===")
}
