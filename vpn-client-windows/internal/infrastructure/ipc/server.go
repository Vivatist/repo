//go:build windows

package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/Microsoft/go-winio"
)

// NamedPipeServer — IPC-сервер через Windows Named Pipe.
type NamedPipeServer struct {
	listener net.Listener
	handler  func(req map[string]interface{}) map[string]interface{}
	mu       sync.Mutex
	stopped  bool
	stopCh   chan struct{} // канал для остановки сервиса по IPC-команде stop_service
}

// NewNamedPipeServer создаёт новый IPC-сервер.
func NewNamedPipeServer() *NamedPipeServer {
	return &NamedPipeServer{}
}

// SetStopCh устанавливает канал для сигнала остановки сервиса.
// Сигнал отправляется при получении IPC-команды "stop_service".
func (s *NamedPipeServer) SetStopCh(ch chan struct{}) {
	s.stopCh = ch
}

// SetHandler устанавливает обработчик запросов.
func (s *NamedPipeServer) SetHandler(handler func(req map[string]interface{}) map[string]interface{}) {
	s.handler = handler
}

// Start запускает IPC-сервер.
func (s *NamedPipeServer) Start() error {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;BU)",
		MessageMode:        false,
		InputBufferSize:    maxMessageSize,
		OutputBufferSize:   maxMessageSize,
	}

	listener, err := winio.ListenPipe(pipeName, cfg)
	if err != nil {
		return fmt.Errorf("listen pipe: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.stopped = false
	s.mu.Unlock()

	log.Printf("[IPC] Сервер запущен на %s", pipeName)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			stopped := s.stopped
			s.mu.Unlock()
			if stopped {
				return nil
			}
			log.Printf("[IPC] Ошибка accept: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Stop останавливает IPC-сервер.
func (s *NamedPipeServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stopped = true
	if s.listener != nil {
		s.listener.Close()
	}
}

// handleConnection обрабатывает одно клиентское соединение.
func (s *NamedPipeServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		// Читаем длину запроса (4 байта, little-endian)
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err != io.EOF {
				log.Printf("[IPC] Ошибка чтения длины: %v", err)
			}
			return
		}

		reqLen := binary.LittleEndian.Uint32(lenBuf)
		if reqLen > maxMessageSize {
			log.Printf("[IPC] Запрос слишком большой: %d байт", reqLen)
			return
		}

		// Читаем тело запроса
		reqData := make([]byte, reqLen)
		if _, err := io.ReadFull(conn, reqData); err != nil {
			log.Printf("[IPC] Ошибка чтения данных: %v", err)
			return
		}

		// Парсим JSON
		var request map[string]interface{}
		if err := json.Unmarshal(reqData, &request); err != nil {
			log.Printf("[IPC] Ошибка JSON: %v", err)
			s.writeResponse(conn, map[string]interface{}{"type": "error", "error": "invalid JSON"})
			continue
		}

		// Обрабатываем запрос
		var response map[string]interface{}
		if s.handler != nil {
			response = s.handler(request)
		} else {
			response = map[string]interface{}{"type": "error", "error": "no handler"}
		}

		// Отправляем ответ
		if err := s.writeResponse(conn, response); err != nil {
			log.Printf("[IPC] Ошибка записи ответа: %v", err)
			return
		}

		// После отправки ответа на stop_service — сигнализируем остановку сервиса
		if reqType, _ := request["type"].(string); reqType == "stop_service" && s.stopCh != nil {
			select {
			case s.stopCh <- struct{}{}:
			default:
			}
			return
		}
	}
}

// writeResponse записывает ответ в соединение.
func (s *NamedPipeServer) writeResponse(conn net.Conn, response map[string]interface{}) error {
	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}

	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}

	return nil
}
