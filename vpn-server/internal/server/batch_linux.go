//go:build linux

// Batch UDP I/O для Linux через sendmmsg/recvmmsg.
//
// sendmmsg/recvmmsg позволяют отправлять/принимать до N пакетов за 1 syscall,
// снижая overhead системных вызовов в 10-30x при высоком pps.
//
// Используется на hot path: tunReadLoop → batchSender.Enqueue → sendmmsg.
package server

import (
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// batchSize — максимальное количество пакетов в одном sendmmsg вызове.
	// 64 — типичный лимит ядра Linux (net.core.wmem_default позволяет).
	batchSize = 64

	// flushInterval — максимальная задержка перед flush батча.
	// 100 мкс — компромисс между latency и throughput.
	// При активном трафике батч обычно заполняется раньше.
	flushInterval = 100 * time.Microsecond
)

// batchEntry — один пакет в очереди на отправку.
type batchEntry struct {
	addr *net.UDPAddr // куда отправлять
	len  int          // длина данных в data
}

// batchSender — батчевая отправка UDP-пакетов через sendmmsg.
//
// Архитектура: single-producer (tunReadLoop) → ring buffer → flush goroutine → sendmmsg.
// Producer шифрует пакеты прямо в пре-аллоцированные буферы, затем вызывает Enqueue.
// Flush goroutine ожидает сигнала или таймаута и вызывает sendmmsg.
type batchSender struct {
	fd int // raw UDP socket fd

	// Пре-аллоцированные буферы данных для каждого слота батча.
	// Каждый буфер достаточно велик для максимального VPN-пакета.
	dataBufs [batchSize][]byte

	// Метаданные пакетов (адрес, длина)
	entries [batchSize]batchEntry

	// Текущее количество пакетов в батче
	count int

	// Время последнего flush (для определения idle period).
	// Если прошло > flushInterval с последнего flush, пакет отправляется немедленно
	// (устраняет задержку для одиночных пакетов: ping, keepalive).
	lastFlush time.Time

	// Мьютекс для синхронизации Enqueue и Flush (минимальный contention:
	// single producer, flush по таймеру или заполнению батча)
	mu sync.Mutex

	// Сигнал flush goroutine: батч полон или нужен flush
	flushCh chan struct{}
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Статистика
	totalSent    uint64
	totalBatches uint64
}

// newBatchSender создаёт новый batch sender.
// fd — file descriptor UDP-сокета (получаем через conn.File().Fd()).
// maxPacketSize — максимальный размер одного VPN-пакета.
func newBatchSender(fd int, maxPacketSize int) *batchSender {
	bs := &batchSender{
		fd:      fd,
		flushCh: make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
	}

	// Пре-аллоцируем буферы для каждого слота
	for i := 0; i < batchSize; i++ {
		bs.dataBufs[i] = make([]byte, maxPacketSize)
	}

	return bs
}

// Start запускает фоновую горутину flush.
func (bs *batchSender) Start() {
	bs.wg.Add(1)
	go bs.flushLoop()
}

// Stop останавливает batch sender, flush'ит оставшиеся пакеты.
func (bs *batchSender) Stop() {
	close(bs.stopCh)
	bs.wg.Wait()

	// Финальный flush
	bs.mu.Lock()
	if bs.count > 0 {
		bs.flushLocked()
	}
	bs.mu.Unlock()
}

// GetBuffer возвращает пре-аллоцированный буфер для текущего слота.
// Вызывается ПЕРЕД Enqueue — producer шифрует данные прямо в этот буфер.
// Вызывать под bs.mu.Lock() не нужно — single producer гарантирует, что
// count не изменится между GetBuffer и Enqueue.
func (bs *batchSender) GetBuffer() []byte {
	bs.mu.Lock()
	idx := bs.count
	bs.mu.Unlock()
	if idx >= batchSize {
		// Батч полон — flush и берём слот 0
		bs.Flush()
		return bs.dataBufs[0]
	}
	return bs.dataBufs[idx]
}

// Enqueue добавляет зашифрованный пакет в батч.
// Данные уже должны быть записаны в буфер, полученный через GetBuffer().
// dataLen — фактическая длина данных в буфере.
//
// Стратегия flush:
//   - Батч полон (64 пакета) → немедленный flush
//   - Одиночный пакет после idle period (> flushInterval) → немедленный flush
//     (устраняет задержку для ping, keepalive, одиночных HTTP-запросов)
//   - Burst-трафик (пакеты приходят чаще flushInterval) → батчатся, flushLoop flush'ит
func (bs *batchSender) Enqueue(addr *net.UDPAddr, dataLen int) {
	bs.mu.Lock()

	idx := bs.count
	if idx >= batchSize {
		// Батч полон — flush и помещаем в начало
		bs.flushLocked()
		idx = 0
	}

	bs.entries[idx] = batchEntry{
		addr: addr,
		len:  dataLen,
	}
	bs.count = idx + 1

	if bs.count >= batchSize {
		// Батч полон — немедленный flush
		bs.flushLocked()
		bs.mu.Unlock()
		return
	}

	// Немедленный flush для одиночных пакетов после idle period.
	// Это устраняет задержку flushInterval (~100мкс-1мс) для
	// латентно-чувствительных пакетов (ping, keepalive, одиночные HTTP).
	// При burst-трафике пакеты по-прежнему батчатся естественным образом.
	if time.Since(bs.lastFlush) >= flushInterval {
		bs.flushLocked()
		bs.mu.Unlock()
		return
	}

	bs.mu.Unlock()

	// Сигнализируем flush goroutine (неблокирующий)
	select {
	case bs.flushCh <- struct{}{}:
	default:
	}
}

// Flush принудительно отправляет все пакеты в батче.
func (bs *batchSender) Flush() {
	bs.mu.Lock()
	if bs.count > 0 {
		bs.flushLocked()
	}
	bs.mu.Unlock()
}

// flushLocked отправляет все пакеты через sendmmsg. Вызывается под bs.mu.Lock().
func (bs *batchSender) flushLocked() {
	n := bs.count
	if n == 0 {
		return
	}

	// Собираем массив mmsghdr для sendmmsg
	msgs := make([]mmsghdr, n)
	iovecs := make([]unix.Iovec, n)
	addrs := make([]unix.RawSockaddrInet4, n)

	for i := 0; i < n; i++ {
		entry := &bs.entries[i]

		// Заполняем sockaddr_in
		addrs[i].Family = unix.AF_INET
		port := uint16(entry.addr.Port)
		addrs[i].Port = (port >> 8) | (port << 8) // htons
		copy(addrs[i].Addr[:], entry.addr.IP.To4())

		// Заполняем iovec
		iovecs[i].Base = &bs.dataBufs[i][0]
		iovecs[i].Len = uint64(entry.len)

		// Заполняем msghdr
		msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
		msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
		msgs[i].Hdr.Iov = &iovecs[i]
		msgs[i].Hdr.Iovlen = 1
	}

	// sendmmsg syscall
	sent, err := sendmmsg(bs.fd, msgs)
	if err != nil {
		log.Printf("[BATCH] sendmmsg ошибка (%d пакетов): %v", n, err)
	}

	bs.totalSent += uint64(sent)
	bs.totalBatches++
	bs.count = 0
	bs.lastFlush = time.Now()
}

// flushLoop — фоновая горутина, вызывающая flush по таймеру.
// Обеспечивает минимальную задержку для неполных батчей.
func (bs *batchSender) flushLoop() {
	defer bs.wg.Done()

	timer := time.NewTimer(flushInterval)
	defer timer.Stop()

	for {
		select {
		case <-bs.stopCh:
			return
		case <-bs.flushCh:
			// Есть данные — ждём немного для накопления батча, затем flush
			timer.Reset(flushInterval)
			select {
			case <-bs.stopCh:
				return
			case <-timer.C:
				bs.Flush()
			}
		}
	}
}

// --- sendmmsg syscall wrapper ---

// mmsghdr — структура для sendmmsg/recvmmsg (аналог C struct mmsghdr).
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte // padding на 64-бит
}

// sendmmsg выполняет системный вызов sendmmsg.
func sendmmsg(fd int, msgs []mmsghdr) (int, error) {
	n, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		0, // flags
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

// recvmmsg выполняет системный вызов recvmmsg.
// timeout = nil — блокирующий вызов (разблокируется при закрытии fd).
func recvmmsg(fd int, msgs []mmsghdr) (int, error) {
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		unix.MSG_WAITFORONE, // возвращаемся после первого пакета (не ждём заполнения)
		0,                   // timeout = NULL
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

// --- Batch receiver для приёма UDP-пакетов ---

const (
	// recvBatchSize — максимальное количество пакетов за один recvmmsg.
	recvBatchSize = 64
)

// batchReceiver — пре-аллоцированные буферы для batch приёма через recvmmsg.
//
// КРИТИЧЕСКИ ВАЖНО: Go создаёт сокеты в неблокирующем режиме (O_NONBLOCK)
// для интеграции с netpoller (epoll). Прямой вызов recvmmsg на таком fd
// возвращает EAGAIN мгновенно при отсутствии данных, вызывая busy spin loop.
//
// Решение: используем syscall.RawConn.Read() для интеграции с Go netpoller.
// Горутина блокируется через epoll (не CPU) пока данные не появятся.
type batchReceiver struct {
	rawConn syscall.RawConn // RawConn для интеграции с Go netpoller

	// Пре-аллоцированные буферы для каждого пакета
	bufs [recvBatchSize][]byte

	// mmsghdr, iovec, sockaddr для каждого слота
	msgs  [recvBatchSize]mmsghdr
	iovs  [recvBatchSize]unix.Iovec
	addrs [recvBatchSize]unix.RawSockaddrInet4
}

// newBatchReceiver создаёт новый batch receiver.
// rawConn — RawConn от net.UDPConn.SyscallConn(), интегрируется с Go netpoller.
func newBatchReceiver(rawConn syscall.RawConn, maxPacketSize int) *batchReceiver {
	br := &batchReceiver{rawConn: rawConn}

	for i := 0; i < recvBatchSize; i++ {
		br.bufs[i] = make([]byte, maxPacketSize)

		br.iovs[i].Base = &br.bufs[i][0]
		br.iovs[i].Len = uint64(maxPacketSize)

		br.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&br.addrs[i]))
		br.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
		br.msgs[i].Hdr.Iov = &br.iovs[i]
		br.msgs[i].Hdr.Iovlen = 1
	}

	return br
}

// Recv принимает пакеты через recvmmsg. Возвращает количество полученных пакетов.
// Каждый пакет доступен через GetPacket(i).
//
// Блокируется через Go netpoller (epoll) до появления данных:
// rawConn.Read() ожидает readability через netpoller,
// затем вызывает recvmmsg() для batch-чтения.
// При EAGAIN возвращает false → netpoller повторно ожидает данных.
func (br *batchReceiver) Recv() (int, error) {
	// Сбрасываем Len для каждого сообщения
	for i := 0; i < recvBatchSize; i++ {
		br.msgs[i].Len = 0
	}

	var n int
	var recvErr error

	// rawConn.Read() блокирует горутину через netpoller (epoll),
	// НЕ потребляя CPU. Когда данные доступны, вызывает callback.
	readErr := br.rawConn.Read(func(fd uintptr) bool {
		n, recvErr = recvmmsg(int(fd), br.msgs[:])
		if recvErr != nil {
			// EAGAIN/EWOULDBLOCK — данных ещё нет, просим netpoller подождать.
			// Это нормальная ситуация на неблокирующем сокете.
			if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK {
				return false // false = retry, netpoller подождёт readability
			}
			return true // реальная ошибка, прекращаем
		}
		return true // успешно получили пакеты
	})

	if readErr != nil {
		return 0, readErr
	}
	return n, recvErr
}

// GetPacket возвращает данные и адрес отправителя для i-го пакета.
func (br *batchReceiver) GetPacket(i int) (data []byte, addr *net.UDPAddr) {
	n := int(br.msgs[i].Len)
	data = br.bufs[i][:n]

	// Извлекаем IP и порт из RawSockaddrInet4
	sa := &br.addrs[i]
	port := int(sa.Port>>8) | int(sa.Port<<8)&0xFF00 // ntohs
	ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
	addr = &net.UDPAddr{IP: ip, Port: port}

	return data, addr
}

// --- Вспомогательные функции для интеграции ---

// getUDPSocketFdAndRawConn извлекает raw file descriptor и RawConn из *net.UDPConn.
// fd нужен для sendmmsg (batch sender).
// rawConn нужен для recvmmsg (batch receiver) — интеграция с Go netpoller.
func getUDPSocketFdAndRawConn(conn *net.UDPConn) (int, syscall.RawConn, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return -1, nil, err
	}
	var fd int
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, nil, err
	}
	return fd, rawConn, nil
}

// --- Batch отправка из TUN в UDP (интеграция с tunReadLoop) ---

// sendToClientBatch шифрует и помещает пакет в батч для отправки.
// Заменяет sendToClient на hot path.
func (s *VPNServer) sendToClientBatch(session *Session, plaintext []byte, bs *batchSender) {
	// Получаем буфер из батча
	buf := bs.GetBuffer()

	n, err := session.EncryptAndBuild(buf, plaintext)
	if err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[SEND] Ошибка шифрования для сессии #%d: %v", session.ID, err)
		}
		return
	}

	bs.Enqueue(session.ClientAddr, n)

	session.BytesSent.Add(uint64(len(plaintext)))
	session.PacketsSent.Add(1)
}
