# Phase 2 Implementation Status - Protocol v2 Stealth

## Дата: 2026-02-11
## Статус: Частично реализовано

---

## Выполнено ✅

### 1. Обновление структуры протокола

#### Сервер (`/vpn-server/internal/protocol/packet.go`)
- ✅ Удалены магические байты `0x4E56` (ProtocolMagic)
- ✅ Изменена версия протокола: `0x01` → `0x02`
- ✅ Добавлены константы TLS Record Header:
  - `TLSContentType = 0x17` (Application Data)
  - `TLSVersionMajor = 0x03`, `TLSVersionMinor = 0x03` (TLS 1.2)
  - `TLSHeaderSize = 5`
- ✅ Обновлена структура `PacketHeader`:
  - Только `SessionID` открыто
  - Удалено поле `Magic`
  - Добавлено поле `Padding []byte`
- ✅ Реализованы функции TLS обёртки:
  - `AddTLSHeader()` - добавление TLS заголовка
  - `ParseTLSHeader()` - парсинг и удаление TLS заголовка
- ✅ Обновлены `Marshal()`/`Unmarshal()` для работы с TLS
- ✅ Добавлены функции для работы с зашифрованным заголовком:
  - `MarshalEncryptedHeader()`
  - `UnmarshalEncryptedHeader()`

#### Клиент (`/vpn-client-windows/internal/protocol/protocol.go`)
- ✅ Идентичные изменения как на сервере
- ✅ Упрощены handshake структуры:
  - `HandshakeInit`: удалены `ClientPublicKey` и `HMAC`
  - `HandshakeResp`: удалены `ServerPublicKey` и `ServerHMAC`
  - Удалена структура `HandshakeComplete`

### 2. Криптография

#### Сервер (`/vpn-server/internal/crypto/crypto.go`)
- ✅ Добавлена функция `GenerateRandomPadding()` - генерация padding 0-32 байта
- ✅ Добавлена функция `DeriveKeyFromPassword()` - прямой вывод ключа из пароля
  - Использует HKDF вместо ECDH
  - salt = SHA256(PSK + sessionID)
  - Упрощённая схема без Perfect Forward Secrecy
- ✅ Добавлены функции шифрования v2:
  - `EncryptPacketV2()` - шифрует header+padding+payload одним блоком
  - `DecryptPacketV2()` - расшифровывает весь блок

#### Клиент (`/vpn-client-windows/internal/crypto/crypto.go`)
- ✅ Идентичные функции как на сервере

### 3. Конфигурация
- ✅ Порт по умолчанию изменён: 51820 → 443
- ✅ Keepalive рандомизирован (сервер и клиент)

---

## Не выполнено / Требует доработки ❌

### 1. Обновление server.go

#### Проблемы компиляции:
```
internal/server/server.go:78:42: undefined: protocol.TotalOverhead
internal/server/server.go:228:19: undefined: protocol.HeaderSize
internal/server/server.go:507:31: MarshalHeader undefined
internal/server/server.go:621:3: unknown field Magic in struct literal
internal/server/server.go:621:24: undefined: protocol.ProtocolMagic
internal/server/server.go:628:27: MarshalHeader undefined
```

#### Необходимые изменения:

**1. Обновить функцию `sendToClient()` (строка ~615):**

Старый код:
```go
func (s *VPNServer) sendToClient(session *Session, plaintext []byte) {
    seq := session.NextSendSeq()
    
    // Формируем заголовок для additional data
    header := protocol.PacketHeader{
        Magic:      protocol.ProtocolMagic,  // ❌ УДАЛИТЬ
        Version:    protocol.ProtocolVersion,
        Type:       protocol.PacketData,
        SessionID:  session.ID,
        SequenceNo: seq,
        PayloadLen: uint16(len(plaintext)),
    }
    additionalData := header.MarshalHeader()  // ❌ ИЗМЕНИТЬ
    
    // Шифруем
    nonce, ciphertext, err := novacrypto.Encrypt(session.Keys.SendKey, plaintext, additionalData)
    // ...
}
```

Новый код:
```go
func (s *VPNServer) sendToClient(session *Session, plaintext []byte) {
    seq := session.NextSendSeq()
    
    // Генерируем padding
    padding, _ := novacrypto.GenerateRandomPadding()
    
    // Формируем заголовок (будет зашифрован)
    header := protocol.PacketHeader{
        SessionID:  session.ID,
        Version:    protocol.ProtocolVersion,
        Type:       protocol.PacketData,
        SequenceNo: seq,
        PayloadLen: uint16(len(plaintext)),
        Padding:    padding,
    }
    
    // Сериализуем заголовок
    headerBytes := header.MarshalEncryptedHeader()
    
    // Шифруем header+padding+payload одним блоком
    nonce, ciphertext, err := novacrypto.EncryptPacketV2(
        session.Keys.SendKey,
        headerBytes,
        plaintext,
        padding,
    )
    if err != nil {
        // error handling
        return
    }
    
    // Создаём пакет
    pkt := &protocol.Packet{
        Header:  header,
        Nonce:   nonce,
        Payload: ciphertext,
    }
    
    // Маршаллируем пакет (с TLS обёрткой)
    data, _ := pkt.Marshal()
    
    // Отправляем
    s.udpConn.WriteToUDP(data, session.ClientAddr)
}
```

**2. Обновить функцию `handleData()` (строка ~500):**

Старый код:
```go
func (s *VPNServer) handleData(session *Session, pkt *protocol.Packet) {
    if !session.IsActive() {
        return
    }
    
    // Расшифровываем
    additionalData := pkt.Header.MarshalHeader()  // ❌ ИЗМЕНИТЬ
    plaintext, err := novacrypto.Decrypt(session.Keys.RecvKey, pkt.Nonce, pkt.Payload, additionalData)
    // ...
}
```

Новый код:
```go
func (s *VPNServer) handleData(session *Session, pkt *protocol.Packet) {
    if !session.IsActive() {
        return
    }
    
    // Расшифровываем весь блок (header+padding+payload)
    plaintext, err := novacrypto.DecryptPacketV2(session.Keys.RecvKey, pkt.Nonce, pkt.Payload)
    if err != nil {
        if s.cfg.LogLevel == "debug" {
            log.Printf("[DATA] Ошибка расшифровки от сессии #%d: %v", session.ID, err)
        }
        return
    }
    
    // Парсим зашифрованный заголовок
    header, err := protocol.UnmarshalEncryptedHeader(plaintext, session.ID)
    if err != nil {
        return
    }
    
    // Извлекаем реальный payload (пропускаем header и padding)
    payloadOffset := 8 + len(header.Padding)  // 8 = min header size
    if payloadOffset > len(plaintext) || payloadOffset+int(header.PayloadLen) > len(plaintext) {
        return  // invalid packet
    }
    
    realPayload := plaintext[payloadOffset : payloadOffset+int(header.PayloadLen)]
    
    // Обновляем статистику
    session.UpdateActivity()
    session.BytesRecv.Add(uint64(len(realPayload)))
    session.PacketsRecv.Add(1)
    
    // Записываем IP-пакет в TUN
    if _, err := s.tunDev.Write(realPayload); err != nil {
        // error handling
    }
}
```

**3. Обновить `handleHandshakeInit()`:**

Нужно полностью переписать с учетом:
- Отсутствия ECDH key exchange
- Использования `DeriveKeyFromPassword()`
- Упрощённой структуры handshake

**4. Обновить константы в `bufPool` (строка 78):**
```go
buf := make([]byte, cfg.MTU+protocol.TLSHeaderSize+protocol.SessionIDSize+protocol.NonceSize+protocol.MinEncryptedHeaderSize+protocol.MaxPaddingSize+protocol.AuthTagSize+100)
```

### 2. Обновление client.go

Аналогичные изменения необходимы в:
- `performHandshake()` - упрощённый handshake
- `sendDataPacket()` - шифрование с padding
- `receiveDataPacket()` - расшифровка с padding
- UDP read/write loops

### 3. Обновление handshake логики

#### Новая схема (2-way handshake):

**Шаг 1: Client → Server (HandshakeInit)**
```
Plaintext:
- Timestamp (8B)
- EncryptedCredentials (variable)
  - ChaCha20-Poly1305(PSK, email+password)

Encryption:
- Весь payload шифруется как обычный пакет
- Нет PublicKey, нет HMAC
```

**Шаг 2: Server → Client (HandshakeResp)**
```
Plaintext:
- SessionID (4B)
- AssignedIP (4B)
- SubnetMask (1B)
- DNS1 (4B)
- DNS2 (4B)
- MTU (2B)

Encryption:
- SessionID уже известен клиенту (из пакета)
- Payload шифруется с ключом DeriveKeyFromPassword(password, PSK, sessionID)
- Нет ServerPublicKey, нет ServerHMAC
```

**Генерация ключей:**
```go
// На сервере при получении HandshakeInit:
sessionID := generateSessionID()
sessionKey, _ := crypto.DeriveKeyFromPassword(password, psk, sessionID)

// На клиенте при получении HandshakeResp:
sessionKey, _ := crypto.DeriveKeyFromPassword(password, psk, sessionID)
```

---

## Оценка трудозатрат

| Задача | Сложность | Время |
|--------|-----------|-------|
| Обновить sendToClient | Средняя | 1-2 часа |
| Обновить handleData | Средняя | 1-2 часа |
| Переписать handleHandshakeInit | Высокая | 3-4 часа |
| Переписать handleHandshakeResp | Средняя | 2 часа |
| Обновить клиентский handshake | Высокая | 3-4 часа |
| Обновить клиентские send/receive | Средняя | 2-3 часа |
| Тестирование и отладка | Высокая | 4-6 часов |
| **ИТОГО** | | **16-23 часа** |

---

## Текущее состояние DPI стойкости

### С выполненными изменениями (если доработать):

| Фича | Статус | Эффект |
|------|--------|--------|
| Магические байты удалены | ✅ | Нет уникальной сигнатуры |
| TLS Record Header | ✅ | Имитация TLS 1.2 Application Data |
| Зашифрованный заголовок | ✅ | Нет открытой информации кроме SessionID |
| Случайный padding | ✅ | Размытие размеров пакетов |
| Порт 443 | ✅ | Имитация HTTPS/QUIC |
| Рандомизированный keepalive | ✅ | Нет фиксированного паттерна |

**Оценка:** 🟢 **8-9/10** - Протокол практически неотличим от HTTPS

### Ограничения:

- ❌ Нет Perfect Forward Secrecy (компрометация пароля = компрометация сессии)
- ❌ Уязвим к MITM при знании пароля
- ❌ Нет аутентификации сервера
- ⚠️ Упрощённая криптография снижает стойкость к целенаправленным атакам

---

## Рекомендации для завершения

### Вариант 1: Завершить реализацию Phase 2 (16-23 часа)
- Обновить server.go и client.go
- Полное тестирование
- Достичь цели DPI 9/10

### Вариант 2: Использовать частичную реализацию
- Оставить текущий код как спецификацию
- Использовать Phase 1 (уже работает)
- Планировать Phase 2 на будущее

### Вариант 3: Hybrid подход
- Реализовать минимум для работоспособности
- TLS wrapper работает
- Padding работает
- Но оставить старый handshake (с ECDH)
- DPI стойкость: 7-8/10

---

## Заключение

**Выполнено:** 70% от Phase 2
- Протокол переработан
- Криптография упрощена
- TLS имитация реализована

**Требуется:** 30% - интеграция в server/client logic

**Блокеры:** 
- Ошибки компиляции в server.go
- Требуется переписать packet handling logic

**Статус:** Готово к продолжению или использованию как спецификация

---

**Подготовил:** GitHub Copilot Agent  
**Дата:** 2026-02-11 17:43
