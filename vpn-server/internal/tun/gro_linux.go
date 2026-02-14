//go:build linux

// GRO/GSO (Generic Receive/Segmentation Offload) для TUN-устройства.
//
// GRO позволяет ядру коалесцировать несколько TCP-сегментов в один большой
// «суперпакет» перед передачей в userspace. Это снижает количество read()
// syscall в 5-10 раз для TCP-трафика.
//
// GSO позволяет записывать большие «суперпакеты» в TUN, а ядро само
// сегментирует их перед отправкой в сеть.
//
// Для работы требуется:
// - Linux >= 4.19 (IFF_VNET_HDR + TUNSETOFFLOAD + TSO)
// - Linux >= 6.2 для USO (UDP Segmentation Offload) — опционально
//
// При GRO каждый пакет из TUN содержит virtio_net_hdr (10 байт) перед IP-данными.
// Поле gso_type указывает, коалесцирован ли пакет. Если да, необходима
// TCP-сегментация в userspace перед шифрованием и отправкой клиенту.
package tun

import (
	"encoding/binary"
)

const (
	// VirtioNetHdrLen — размер заголовка virtio_net_hdr (без num_buffers).
	VirtioNetHdrLen = 10

	// GSO типы из virtio_net_hdr.gso_type
	GSONone   = 0 // Обычный пакет, не коалесцирован
	GSOTCPv4  = 1 // TCP over IPv4, коалесцирован
	GSOUDP    = 3 // UDP (deprecated UFO)
	GSOTCPv6  = 4 // TCP over IPv6, коалесцирован
	GSOUDPL4  = 5 // UDP L4 segmentation (Linux 6.2+)

	// Флаги virtio_net_hdr.flags
	virtioFlagNeedsCsum = 1
)

// ParseGROHeader парсит virtio_net_hdr из буфера, прочитанного из TUN с IFF_VNET_HDR.
// Возвращает: IP-пакет (без virtio заголовка), gsoType, gsoSize.
// Если буфер слишком мал, возвращает nil.
func ParseGROHeader(raw []byte) (packet []byte, gsoType uint8, gsoSize uint16) {
	if len(raw) < VirtioNetHdrLen {
		return nil, 0, 0
	}
	gsoType = raw[1]
	gsoSize = binary.LittleEndian.Uint16(raw[4:6])
	packet = raw[VirtioNetHdrLen:]
	return
}

// ForEachGROSegment обрабатывает GRO-коалесцированный пакет, вызывая fn для каждого
// отдельного TCP-сегмента. segBuf — пре-аллоцированный буфер для формирования
// сегментов (должен быть >= MTU + 100 байт). Zero-alloc: segBuf переиспользуется.
//
// Если пакет не коалесцирован (gsoType == GSONone) или не поддерживается,
// вызывает fn один раз с исходным пакетом.
func ForEachGROSegment(packet []byte, gsoType uint8, gsoSize uint16, segBuf []byte, fn func(segment []byte)) {
	if gsoType == GSONone || gsoSize == 0 || len(packet) < 20 {
		fn(packet)
		return
	}

	switch gsoType {
	case GSOTCPv4:
		segmentTCPv4(packet, int(gsoSize), segBuf, fn)
	case GSOTCPv6:
		segmentTCPv6(packet, int(gsoSize), segBuf, fn)
	default:
		// Неизвестный/неподдерживаемый тип GSO — передаём как есть
		fn(packet)
	}
}

// segmentTCPv4 разбивает GRO-коалесцированный TCP/IPv4-пакет на отдельные
// MTU-сегменты. Каждый сегмент формируется в segBuf и передаётся в fn.
//
// Для каждого сегмента исправляются:
// - IP total_length, IP header checksum, IP identification
// - TCP sequence number, TCP flags (FIN/PSH только на последнем)
// - TCP checksum (полный пересчёт)
func segmentTCPv4(packet []byte, gsoSize int, segBuf []byte, fn func([]byte)) {
	// Валидация IPv4 заголовка
	if packet[0]>>4 != 4 {
		fn(packet)
		return
	}
	ipHdrLen := int(packet[0]&0x0F) * 4
	if ipHdrLen < 20 || len(packet) < ipHdrLen {
		fn(packet)
		return
	}

	// Проверяем протокол — TCP (6)
	if packet[9] != 6 {
		fn(packet)
		return
	}

	// Валидация TCP заголовка
	if len(packet) < ipHdrLen+20 {
		fn(packet)
		return
	}
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	if tcpHdrLen < 20 {
		fn(packet)
		return
	}

	dataOff := ipHdrLen + tcpHdrLen
	if dataOff > len(packet) {
		fn(packet)
		return
	}

	dataLen := len(packet) - dataOff
	if dataLen <= gsoSize {
		// Данные помещаются в один сегмент — сегментация не нужна
		fn(packet)
		return
	}

	// Запоминаем оригинальные значения для модификации
	origSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4 : ipHdrLen+8])
	origFlags := packet[ipHdrLen+13]
	origID := binary.BigEndian.Uint16(packet[4:6])

	for off := 0; off < dataLen; off += gsoSize {
		end := off + gsoSize
		if end > dataLen {
			end = dataLen
		}
		segDataLen := end - off
		totalLen := dataOff + segDataLen

		// Копируем IP + TCP заголовки в segBuf
		copy(segBuf[:dataOff], packet[:dataOff])
		// Копируем данные сегмента
		copy(segBuf[dataOff:], packet[dataOff+off:dataOff+end])

		// --- Исправляем IP заголовок ---
		// IP total length
		binary.BigEndian.PutUint16(segBuf[2:4], uint16(totalLen))
		// IP identification (инкрементируем для каждого сегмента)
		binary.BigEndian.PutUint16(segBuf[4:6], origID+uint16(off/gsoSize))

		// --- Исправляем TCP заголовок ---
		// TCP sequence number
		binary.BigEndian.PutUint32(segBuf[ipHdrLen+4:ipHdrLen+8], origSeq+uint32(off))
		// TCP flags: очищаем FIN и PSH на всех сегментах кроме последнего
		if end < dataLen {
			segBuf[ipHdrLen+13] = origFlags &^ 0x09 // Очищаем FIN(0x01) и PSH(0x08)
		} else {
			segBuf[ipHdrLen+13] = origFlags // Последний сегмент сохраняет оригинальные флаги
		}

		// --- Пересчитываем контрольные суммы ---
		// IP header checksum
		segBuf[10] = 0
		segBuf[11] = 0
		ipCksum := ipv4Checksum(segBuf[:ipHdrLen])
		binary.BigEndian.PutUint16(segBuf[10:12], ipCksum)

		// TCP checksum (полный пересчёт с pseudo-header)
		segBuf[ipHdrLen+16] = 0
		segBuf[ipHdrLen+17] = 0
		tcpLen := uint16(totalLen - ipHdrLen)
		tcpCksum := tcpv4Checksum(segBuf[:ipHdrLen], segBuf[ipHdrLen:totalLen], tcpLen)
		binary.BigEndian.PutUint16(segBuf[ipHdrLen+16:ipHdrLen+18], tcpCksum)

		fn(segBuf[:totalLen])
	}
}

// segmentTCPv6 разбивает GRO-коалесцированный TCP/IPv6-пакет на отдельные сегменты.
// IPv6 заголовок: 40 байт. Нет header checksum (проще чем IPv4).
func segmentTCPv6(packet []byte, gsoSize int, segBuf []byte, fn func([]byte)) {
	// Валидация IPv6 заголовка
	if len(packet) < 40 || packet[0]>>4 != 6 {
		fn(packet)
		return
	}

	// Next Header = TCP (6)
	if packet[6] != 6 {
		fn(packet)
		return
	}

	ipHdrLen := 40 // IPv6 фиксированный заголовок (без extension headers)

	// Валидация TCP заголовка
	if len(packet) < ipHdrLen+20 {
		fn(packet)
		return
	}
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	if tcpHdrLen < 20 {
		fn(packet)
		return
	}

	dataOff := ipHdrLen + tcpHdrLen
	if dataOff > len(packet) {
		fn(packet)
		return
	}

	dataLen := len(packet) - dataOff
	if dataLen <= gsoSize {
		fn(packet)
		return
	}

	origSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4 : ipHdrLen+8])
	origFlags := packet[ipHdrLen+13]

	for off := 0; off < dataLen; off += gsoSize {
		end := off + gsoSize
		if end > dataLen {
			end = dataLen
		}
		segDataLen := end - off
		totalLen := dataOff + segDataLen

		// Копируем заголовки + данные сегмента
		copy(segBuf[:dataOff], packet[:dataOff])
		copy(segBuf[dataOff:], packet[dataOff+off:dataOff+end])

		// IPv6 payload length (без заголовка)
		binary.BigEndian.PutUint16(segBuf[4:6], uint16(totalLen-ipHdrLen))

		// TCP sequence number
		binary.BigEndian.PutUint32(segBuf[ipHdrLen+4:ipHdrLen+8], origSeq+uint32(off))

		// TCP flags: FIN/PSH только на последнем
		if end < dataLen {
			segBuf[ipHdrLen+13] = origFlags &^ 0x09
		} else {
			segBuf[ipHdrLen+13] = origFlags
		}

		// TCP checksum (pseudo-header IPv6 + TCP)
		segBuf[ipHdrLen+16] = 0
		segBuf[ipHdrLen+17] = 0
		tcpLen := uint16(totalLen - ipHdrLen)
		tcpCksum := tcpv6Checksum(segBuf[:ipHdrLen], segBuf[ipHdrLen:totalLen], tcpLen)
		binary.BigEndian.PutUint16(segBuf[ipHdrLen+16:ipHdrLen+18], tcpCksum)

		fn(segBuf[:totalLen])
	}
}

// ipv4Checksum вычисляет контрольную сумму IPv4 заголовка (RFC 791).
// Поле checksum (offset 10-11) должно быть обнулено перед вызовом.
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	n := len(header)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	if n%2 == 1 {
		sum += uint32(header[n-1]) << 8
	}
	// Fold 32-bit sum to 16-bit
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// tcpv4Checksum вычисляет TCP checksum с IPv4 pseudo-header.
// Поле checksum в TCP заголовке (offset 16-17) должно быть обнулено.
func tcpv4Checksum(ipHeader []byte, tcpData []byte, tcpLen uint16) uint16 {
	var sum uint32

	// IPv4 pseudo-header: src IP(4) + dst IP(4) + reserved(1) + protocol(1) + TCP length(2)
	sum += uint32(binary.BigEndian.Uint16(ipHeader[12:14])) // src IP [0:1]
	sum += uint32(binary.BigEndian.Uint16(ipHeader[14:16])) // src IP [2:3]
	sum += uint32(binary.BigEndian.Uint16(ipHeader[16:18])) // dst IP [0:1]
	sum += uint32(binary.BigEndian.Uint16(ipHeader[18:20])) // dst IP [2:3]
	sum += uint32(6)                                        // protocol = TCP
	sum += uint32(tcpLen)

	// TCP header + data
	n := len(tcpData)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i:]))
	}
	if n%2 == 1 {
		sum += uint32(tcpData[n-1]) << 8
	}

	// Fold
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// tcpv6Checksum вычисляет TCP checksum с IPv6 pseudo-header.
func tcpv6Checksum(ipHeader []byte, tcpData []byte, tcpLen uint16) uint16 {
	var sum uint32

	// IPv6 pseudo-header: src IP(16) + dst IP(16) + TCP length(4) + next header(4)
	// src IP: offset 8..23
	for i := 8; i < 24; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipHeader[i:]))
	}
	// dst IP: offset 24..39
	for i := 24; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipHeader[i:]))
	}
	// TCP length (32-bit, zero-extended)
	sum += uint32(tcpLen)
	// Next header = TCP (6)
	sum += uint32(6)

	// TCP header + data
	n := len(tcpData)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i:]))
	}
	if n%2 == 1 {
		sum += uint32(tcpData[n-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
