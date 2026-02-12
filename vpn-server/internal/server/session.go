// Package server реализует управление клиентскими сессиями VPN.
package server

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	mu sync.RWMutex

	// ID — уникальный идентификатор сессии
	ID uint32

	// ClientAddr — UDP-адрес клиента
	ClientAddr *net.UDPAddr

	// AssignedIP — назначенный IP внутри VPN
	AssignedIP net.IP

	// State — состояние сессии
	State SessionState

	// Keys — сессионные ключи шифрования
	Keys *protocol.SessionKeys

	// ServerKeyPair — ephemeral ключевая пара сервера для этой сессии
	ServerKeyPair *protocol.KeyPair

	// SendSeq — счётчик исходящих пакетов
	SendSeq atomic.Uint32

	// RecvSeq — последний принятый номер пакета (для anti-replay)
	RecvSeq atomic.Uint32

	// CreatedAt — время создания сессии
	CreatedAt time.Time

	// LastActivity — время последней активности
	LastActivity time.Time

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
	return &Session{
		ID:           id,
		ClientAddr:   clientAddr,
		State:        SessionStateHandshake,
		CreatedAt:    now,
		LastActivity: now,
	}
}

// UpdateActivity обновляет время последней активности.
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// GetLastActivity возвращает время последней активности.
func (s *Session) GetLastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastActivity
}

// NextSendSeq возвращает и увеличивает счётчик исходящих пакетов.
func (s *Session) NextSendSeq() uint32 {
	return s.SendSeq.Add(1) - 1
}

// SetState устанавливает состояние сессии.
func (s *Session) SetState(state SessionState) {
	s.mu.Lock()
	s.State = state
	s.mu.Unlock()
}

// GetState возвращает состояние сессии.
func (s *Session) GetState() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

// IsActive проверяет, активна ли сессия.
func (s *Session) IsActive() bool {
	return s.GetState() == SessionStateActive
}

// SessionManager управляет всеми активными сессиями.
type SessionManager struct {
	mu sync.RWMutex

	// sessions — карта: sessionID -> Session
	sessions map[uint32]*Session

	// ipToSession — карта: VPN IP -> Session (для маршрутизации)
	ipToSession map[string]*Session

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
		ipToSession:    make(map[string]*Session),
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
	sm.ipToSession[assignedIP.String()] = session
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
	return sm.ipToSession[ip.String()]
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
		delete(sm.ipToSession, session.AssignedIP.String())
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
		delete(sm.ipToSession, session.AssignedIP.String())
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
		sm.ipToSession[newIP.String()] = session
		return
	}

	session.AssignedIP = fixedIP
	sm.ipToSession[fixedIP.String()] = session
	log.Printf("[SESSION] Сессии #%d назначен фиксированный IP: %s", session.ID, fixedIP)
}
