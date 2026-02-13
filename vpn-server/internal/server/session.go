// Package server реализует управление клиентскими сессиями VPN.
package server

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/novavpn/vpn-server/internal/protocol"
)

// SessionState — состояние сессии.
type SessionState int

const (
	// SessionStateHandshake — сессия в процессе рукопожатия
	SessionStateHandshake SessionState = iota

	// SessionStateActive — сессия активна
	SessionStateActive

	// SessionStateExpired — сессия истекла
	SessionStateExpired
)

// String возвращает строковое представление состояния.
func (s SessionState) String() string {
	switch s {
	case SessionStateHandshake:
		return "handshake"
	case SessionStateActive:
		return "active"
	case SessionStateExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Session представляет VPN-сессию клиента.
type Session struct {
	// ID — уникальный идентификатор сессии
	ID uint32

	// ClientAddr — UDP-адрес клиента
	ClientAddr *net.UDPAddr

	// AssignedIP — назначенный IP внутри VPN
	AssignedIP net.IP

	// assignedKey — [4]byte ключ для быстрого lookup по IP (без аллокаций)
	assignedKey [4]byte

	// state — состояние сессии (atomic, без мьютекса)
	state atomic.Int32

	// Keys — сессионные ключи шифрования
	Keys *protocol.SessionKeys

	// sendAEAD — кешированный AEAD для шифрования (создаётся один раз при handshake)
	sendAEAD cipher.AEAD
	// recvAEAD — кешированный AEAD для дешифрования
	recvAEAD cipher.AEAD

	// Counter-nonce: prefix(4) + counter(8) = 12 байт nonce.
	// Prefix выводится из ключа (обе стороны вычисляют одинаково), на wire только counter(4).
	noncePrefix     [4]byte       // deriveNoncePrefix(sendKey)
	recvNoncePrefix [4]byte       // deriveNoncePrefix(recvKey)
	sendCounter     atomic.Uint64 // инкрементируется на каждый пакет

	// ServerKeyPair — ephemeral ключевая пара сервера для этой сессии
	ServerKeyPair *protocol.KeyPair

	// SendSeq — счётчик исходящих пакетов
	SendSeq atomic.Uint32

	// RecvSeq — последний принятый номер пакета (для anti-replay)
	RecvSeq atomic.Uint32

	// CreatedAt — время создания сессии
	CreatedAt time.Time

	// lastActivity — время последней активности (unix timestamp, atomic)
	lastActivity atomic.Int64

	// BytesSent — отправлено байтов
	BytesSent atomic.Uint64

	// BytesRecv — получено байтов
	BytesRecv atomic.Uint64

	// PacketsSent — отправлено пакетов
	PacketsSent atomic.Uint64

	// PacketsRecv — получено пакетов
	PacketsRecv atomic.Uint64

	// ClientName — имя клиента (если известно)
	ClientName string
}

// NewSession создаёт новую сессию.
func NewSession(id uint32, clientAddr *net.UDPAddr) *Session {
	now := time.Now()
	s := &Session{
		ID:         id,
		ClientAddr: clientAddr,
		CreatedAt:  now,
	}
	s.state.Store(int32(SessionStateHandshake))
	s.lastActivity.Store(now.Unix())
	return s
}

// UpdateActivity обновляет время последней активности (lock-free).
func (s *Session) UpdateActivity() {
	s.lastActivity.Store(time.Now().Unix())
}

// GetLastActivity возвращает время последней активности.
func (s *Session) GetLastActivity() time.Time {
	return time.Unix(s.lastActivity.Load(), 0)
}

// NextSendSeq возвращает и увеличивает счётчик исходящих пакетов.
func (s *Session) NextSendSeq() uint32 {
	return s.SendSeq.Add(1) - 1
}

// SetState устанавливает состояние сессии (lock-free).
func (s *Session) SetState(state SessionState) {
	s.state.Store(int32(state))
}

// GetState возвращает состояние сессии (lock-free).
func (s *Session) GetState() SessionState {
	return SessionState(s.state.Load())
}

// IsActive проверяет, активна ли сессия.
func (s *Session) IsActive() bool {
	return s.GetState() == SessionStateActive
}

// InitCrypto инициализирует кешированные AEAD-инстансы из сессионных ключей.
// Вызывается один раз при завершении handshake.
func (s *Session) InitCrypto() error {
	var err error
	s.sendAEAD, err = chacha20poly1305.New(s.Keys.SendKey[:])
	if err != nil {
		return fmt.Errorf("init send AEAD: %w", err)
	}
	s.recvAEAD, err = chacha20poly1305.New(s.Keys.RecvKey[:])
	if err != nil {
		return fmt.Errorf("init recv AEAD: %w", err)
	}

	// Nonce prefix выводится из ключа (обе стороны вычисляют одинаково)
	s.noncePrefix = deriveNoncePrefix(s.Keys.SendKey[:])
	s.recvNoncePrefix = deriveNoncePrefix(s.Keys.RecvKey[:])

	return nil
}

// deriveNoncePrefix выводит 4-байтный nonce prefix из ключа.
func deriveNoncePrefix(key []byte) [4]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("nova-nonce-prefix"))
	sum := mac.Sum(nil)
	var prefix [4]byte
	copy(prefix[:], sum[:4])
	return prefix
}

// EncryptAndBuild шифрует plaintext и собирает готовый VPN-пакет в buf.
// Plain ChaCha20 (XOR) без Poly1305 — нет auth tag.
// Формат: TLS_Header(5) + SessionID(4) + Type(1) + Counter(4) + Ciphertext
func (s *Session) EncryptAndBuild(buf []byte, plaintext []byte) (int, error) {
	ciphertextLen := len(plaintext)      // без overhead: plain XOR
	dataLen := 4 + 1 + 4 + ciphertextLen // SID + Type + Counter + CT
	totalLen := protocol.TLSHeaderSize + dataLen

	if len(buf) < totalLen {
		return 0, fmt.Errorf("buffer too small: %d < %d", len(buf), totalLen)
	}

	// TLS Record Header (имитация TLS 1.2 Application Data)
	buf[0] = 0x17 // Application Data
	buf[1] = 0x03
	buf[2] = 0x03 // TLS 1.2
	binary.BigEndian.PutUint16(buf[3:5], uint16(dataLen))

	// SessionID
	binary.BigEndian.PutUint32(buf[5:9], s.ID)

	// Type
	buf[9] = byte(protocol.PacketData)

	ctr := s.sendCounter.Add(1)
	wireCtr := uint32(ctr) // truncate to 32 bit — nonce и wire используют одно значение

	// Полный nonce: prefix(4) + truncated counter(8)
	var nonce [protocol.NonceSize]byte
	copy(nonce[0:4], s.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], uint64(wireCtr))

	// На wire только counter (4 байта)
	binary.BigEndian.PutUint32(buf[10:14], wireCtr)

	// Plain ChaCha20 XOR прямо в buf[14:]
	c, err := chacha20.NewUnauthenticatedCipher(s.Keys.SendKey[:], nonce[:])
	if err != nil {
		return 0, fmt.Errorf("chacha20 init: %w", err)
	}
	c.XORKeyStream(buf[14:14+len(plaintext)], plaintext)

	return totalLen, nil
}

// ipToKey конвертирует net.IP в [4]byte ключ для map lookup без аллокаций.
func ipToKey(ip net.IP) [4]byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return [4]byte{}
	}
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
}

// SessionManager управляет всеми активными сессиями.
type SessionManager struct {
	mu sync.RWMutex

	// sessions — карта: sessionID -> Session
	sessions map[uint32]*Session

	// ipToSession — карта: VPN IP -> Session ([4]byte ключ, без аллокаций)
	ipToSession map[[4]byte]*Session

	// addrToSession — карта: UDP addr -> Session (для приёма пакетов)
	addrToSession map[string]*Session

	// nextSessionID — следующий доступный ID сессии
	nextSessionID atomic.Uint32

	// ipPool — пул IP-адресов для клиентов
	ipPool *IPPool

	// maxSessions — максимальное количество сессий
	maxSessions int

	// sessionTimeout — таймаут неактивной сессии
	sessionTimeout time.Duration
}

// NewSessionManager создаёт менеджер сессий.
func NewSessionManager(vpnSubnet string, serverIP string, maxSessions int, sessionTimeout time.Duration) (*SessionManager, error) {
	pool, err := NewIPPool(vpnSubnet, serverIP)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания IP-пула: %w", err)
	}

	sm := &SessionManager{
		sessions:       make(map[uint32]*Session),
		ipToSession:    make(map[[4]byte]*Session),
		addrToSession:  make(map[string]*Session),
		ipPool:         pool,
		maxSessions:    maxSessions,
		sessionTimeout: sessionTimeout,
	}

	sm.nextSessionID.Store(1)

	return sm, nil
}

// CreateSession создаёт новую сессию для клиента.
func (sm *SessionManager) CreateSession(clientAddr *net.UDPAddr) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= sm.maxSessions {
		return nil, fmt.Errorf("достигнут лимит сессий (%d)", sm.maxSessions)
	}

	// Проверяем, нет ли уже сессии для этого адреса
	addrKey := clientAddr.String()
	if existingSession, ok := sm.addrToSession[addrKey]; ok {
		// Удаляем старую сессию
		sm.removeSessionLocked(existingSession)
	}

	// Выделяем IP-адрес из пула
	assignedIP, err := sm.ipPool.Allocate()
	if err != nil {
		return nil, fmt.Errorf("не удалось выделить IP: %w", err)
	}

	sessionID := sm.nextSessionID.Add(1) - 1
	session := NewSession(sessionID, clientAddr)
	session.AssignedIP = assignedIP

	sm.sessions[sessionID] = session
	key := ipToKey(assignedIP)
	session.assignedKey = key
	sm.ipToSession[key] = session
	sm.addrToSession[addrKey] = session

	log.Printf("[SESSION] Создана сессия #%d для %s -> VPN IP: %s",
		sessionID, clientAddr.String(), assignedIP.String())

	return session, nil
}

// GetSessionByID возвращает сессию по ID.
func (sm *SessionManager) GetSessionByID(id uint32) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

// GetSessionByAddr возвращает сессию по UDP-адресу клиента.
func (sm *SessionManager) GetSessionByAddr(addr *net.UDPAddr) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.addrToSession[addr.String()]
}

// GetSessionByVPNIP возвращает сессию по назначенному VPN IP.
func (sm *SessionManager) GetSessionByVPNIP(ip net.IP) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.ipToSession[ipToKey(ip)]
}

// RemoveSession удаляет сессию.
func (sm *SessionManager) RemoveSession(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.removeSessionLocked(session)
}

// removeSessionLocked удаляет сессию (вызывается под lock).
func (sm *SessionManager) removeSessionLocked(session *Session) {
	if session == nil {
		return
	}

	session.SetState(SessionStateExpired)

	// Освобождаем IP-адрес
	if session.AssignedIP != nil {
		sm.ipPool.Release(session.AssignedIP)
		delete(sm.ipToSession, session.assignedKey)
	}

	// Удаляем из карт
	delete(sm.sessions, session.ID)
	if session.ClientAddr != nil {
		delete(sm.addrToSession, session.ClientAddr.String())
	}

	// Обнуляем ключи
	if session.Keys != nil {
		protocol.ZeroKey(&session.Keys.SendKey)
		protocol.ZeroKey(&session.Keys.RecvKey)
		protocol.ZeroKey(&session.Keys.HMACKey)
	}

	log.Printf("[SESSION] Удалена сессия #%d (клиент: %s, VPN IP: %s, отправлено: %d, получено: %d)",
		session.ID,
		session.ClientAddr,
		session.AssignedIP,
		session.BytesSent.Load(),
		session.BytesRecv.Load(),
	)
}

// UpdateClientAddr обновляет UDP-адрес клиента при address migration.
// Исправляет addrToSession mapping, предотвращая stale entries.
func (sm *SessionManager) UpdateClientAddr(session *Session, newAddr *net.UDPAddr) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Удаляем старый адрес из маппинга
	if session.ClientAddr != nil {
		delete(sm.addrToSession, session.ClientAddr.String())
	}

	// Обновляем адрес и маппинг
	session.ClientAddr = newAddr
	sm.addrToSession[newAddr.String()] = session
}

// CleanupExpired удаляет истёкшие сессии. Вызывается периодически.
func (sm *SessionManager) CleanupExpired() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	removed := 0
	now := time.Now()

	for _, session := range sm.sessions {
		if now.Sub(session.GetLastActivity()) > sm.sessionTimeout {
			log.Printf("[SESSION] Сессия #%d истекла (последняя активность: %s)",
				session.ID, session.GetLastActivity().Format(time.RFC3339))
			sm.removeSessionLocked(session)
			removed++
		}
	}

	return removed
}

// ActiveCount возвращает количество активных сессий.
func (sm *SessionManager) ActiveCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, s := range sm.sessions {
		if s.GetState() == SessionStateActive {
			count++
		}
	}
	return count
}

// TotalCount возвращает общее количество сессий.
func (sm *SessionManager) TotalCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetAllSessions возвращает копию списка всех сессий.
func (sm *SessionManager) GetAllSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// ReleaseAndReassignIP освобождает автоматически выделенный IP и назначает фиксированный.
func (sm *SessionManager) ReleaseAndReassignIP(session *Session, fixedIP net.IP) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Убираем старый IP из маппинга
	if session.AssignedIP != nil {
		delete(sm.ipToSession, session.assignedKey)
		sm.ipPool.Release(session.AssignedIP)
	}

	// Пытаемся выделить фиксированный IP
	if err := sm.ipPool.AllocateSpecific(fixedIP); err != nil {
		// Если не получилось — оставляем как есть, но логируем
		log.Printf("[SESSION] Не удалось назначить фиксированный IP %s: %v, используем автоматический", fixedIP, err)
		// Пере-выделяем IP из пула
		newIP, allocErr := sm.ipPool.Allocate()
		if allocErr != nil {
			log.Printf("[SESSION] КРИТИЧЕСКАЯ ОШИБКА: не удалось выделить IP: %v", allocErr)
			return
		}
		session.AssignedIP = newIP
		session.assignedKey = ipToKey(newIP)
		sm.ipToSession[session.assignedKey] = session
		return
	}

	session.AssignedIP = fixedIP
	session.assignedKey = ipToKey(fixedIP)
	sm.ipToSession[session.assignedKey] = session
	log.Printf("[SESSION] Сессии #%d назначен фиксированный IP: %s", session.ID, fixedIP)
}
