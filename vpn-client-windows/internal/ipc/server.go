package ipc

import (
	"encoding/json"
	"log"
	"net"
	"sync"

	"github.com/Microsoft/go-winio"
)

// ConnectHandler — обработчик команды подключения.
type ConnectHandler func(params ConnectParams) error

// DisconnectHandler — обработчик команды отключения.
type DisconnectHandler func()

// StatusHandler — обработчик запроса статуса.
type StatusHandler func() StatusInfo

// Server — IPC-сервер, слушает Named Pipe.
type Server struct {
	listener     net.Listener
	onConnect    ConnectHandler
	onDisconnect DisconnectHandler
	onStatus     StatusHandler
	mu           sync.Mutex
	closed       bool
}

// NewServer создаёт IPC-сервер с обработчиками команд.
func NewServer(onConnect ConnectHandler, onDisconnect DisconnectHandler, onStatus StatusHandler) *Server {
	return &Server{
		onConnect:    onConnect,
		onDisconnect: onDisconnect,
		onStatus:     onStatus,
	}
}

// Start запускает прослушивание Named Pipe.
func (s *Server) Start() error {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: PipeSecurity,
	}

	l, err := winio.ListenPipe(PipeName, cfg)
	if err != nil {
		return err
	}
	s.listener = l

	go s.acceptLoop()
	log.Printf("[IPC] Сервер запущен: %s", PipeName)
	return nil
}

// Stop останавливает IPC-сервер.
func (s *Server) Stop() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if s.listener != nil {
		s.listener.Close()
	}
	log.Println("[IPC] Сервер остановлен")
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			log.Printf("[IPC] Accept error: %v", err)
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	var req Request
	if err := ReadMsg(conn, &req); err != nil {
		log.Printf("[IPC] Ошибка чтения запроса: %v", err)
		return
	}

	log.Printf("[IPC] Получена команда: %s", req.Type)

	switch req.Type {
	case CmdConnect:
		var params ConnectParams
		if err := json.Unmarshal(req.Payload, &params); err != nil {
			s.sendError(conn, "неверные параметры: "+err.Error())
			return
		}
		if err := s.onConnect(params); err != nil {
			s.sendError(conn, err.Error())
			return
		}
		s.sendOK(conn)

	case CmdDisconnect:
		s.onDisconnect()
		s.sendOK(conn)

	case CmdGetStatus:
		status := s.onStatus()
		payload, _ := json.Marshal(status)
		WriteMsg(conn, &Response{Type: RespStatus, Payload: payload})

	default:
		s.sendError(conn, "неизвестная команда: "+req.Type)
	}
}

func (s *Server) sendOK(conn net.Conn) {
	WriteMsg(conn, &Response{Type: RespOK})
}

func (s *Server) sendError(conn net.Conn, msg string) {
	WriteMsg(conn, &Response{Type: RespError, Error: msg})
}
