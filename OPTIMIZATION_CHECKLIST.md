# NovaVPN — Чеклист оптимизации скорости

> Цель: ускорить передачу пакетов и установку соединения.  
> Ограничение: маскировка под TLS **не ухудшается** (наоборот, будем усиливать).  
> Допускается: ослабление/отказ от шифрования данных.

---

## Фаза 1: Counter-nonce (убрать crypto/rand из hot path)

**Проблема**: на каждый пакет вызывается `crypto/rand.Read(12 bytes)` — сисколл к CSPRNG ядра ОС (~1 мкс).

**Решение**: атомарный счётчик вместо случайного nonce.
```
nonce[0:4]  = random prefix (генерируется 1 раз при создании сессии)
nonce[4:12] = atomic uint64 counter (инкрементируется на каждый пакет)
```
ChaCha20 требует **уникальность** nonce (не случайность). Counter-nonce — стандартная практика (TLS 1.3).

- [x] Клиент: `crypto/session.go` — добавить `sendCounter atomic.Uint64` + `noncePrefix [4]byte`
- [x] Клиент: `EncryptInto()` — counter вместо `rand.Read`
- [x] Сервер: `session.go` — добавить `sendCounter atomic.Uint64` + `noncePrefix [4]byte`
- [x] Сервер: `EncryptAndBuild()` — counter вместо `rand.Read`
- [x] Скомпилировать клиент
- [x] Скомпилировать сервер

**Эффект**: убирает ~1 мкс сисколл с каждого пакета. При 100k pps = 100мс CPU/сек.  
**Маскировка**: не влияет (nonce передаётся открыто, DPI его не анализирует).

---

## Фаза 2: Убрать SetReadDeadline из цикла (клиент)

**Проблема**: `conn.SetReadDeadline(time.Now().Add(2s))` на каждой итерации — 2 сисколла (`time.Now` + `ioctl`).

**Решение**: использовать `conn.Close()` для прерывания блокирующего `Read`.

- [x] Клиент: `client.go` — убрать `SetReadDeadline` из `udpReadLoop`, закрывать conn при остановке
- [x] Скомпилировать клиент

**Эффект**: убирает 2 сисколла с каждой итерации приёма.  
**Маскировка**: не влияет.

---

## Фаза 3: 1-RTT handshake (ускорение установки соединения)

**Проблема**: 3-way handshake = 1.5 RTT (Init → Resp → Complete). Клиент ждёт отправки Complete перед стартом туннеля.

**Решение**: после получения HandshakeResp клиент начинает передачу данных немедленно. HandshakeComplete отправляется fire-and-forget. Сервер активирует сессию сразу после отправки Resp.

- [x] Клиент: `performer.go` — `sendHandshakeComplete` не блокирует Connect
- [x] Клиент: `client.go` — запуск TUN/UDP loops сразу после Resp
- [x] Сервер: `handler.go` — `handleHandshakeInit` активирует сессию при отправке Resp
- [x] Сервер: `handler.go` — `handleHandshakeComplete` только подтверждение (не блокирует)
- [x] Скомпилировать оба

**Эффект**: соединение устанавливается на 0.5 RTT быстрее (50-150мс).  
**Маскировка**: не влияет.

---

## Фаза 4: Compact wire format (-8 байт/пакет)

**Проблема**: nonce (12B) передаётся в каждом data-пакете, хотя при counter-nonce обе стороны могут его вычислить.

**Решение**: на wire передаётся только 4-byte counter вместо 12-byte nonce. Prefix (4B) выводится детерминистически из ключа через HMAC.

Новый формат data-пакета:
```
TLS_Header(5) + SessionID(4) + Type(1) + Counter(4) + Ciphertext
```
Overhead: **14 байт** вместо 22 (без auth tag) или 38 (с auth tag).

> Handshake-пакеты сохраняют nonce в wire (они редкие, и у них нет counter).

- [x] Nonce prefix derive: `HMAC(key, "nova-nonce-prefix")[:4]` — обе стороны вычисляют одинаково
- [x] Клиент: `EncryptInto` — пишет counter(4) вместо nonce(12)
- [x] Клиент: `DecryptWithCounter(counter uint32, ...)` — восстанавливает nonce из counter + prefix
- [x] Клиент: `handleUDPPacket` — парсит counter(4) вместо nonce(12)
- [x] Сервер: `EncryptAndBuild` — пишет counter(4) вместо nonce(12)
- [x] Сервер: `udpReadLoop` inline — восстанавливает nonce из counter + prefix
- [x] Скомпилировать оба

**Эффект**: -8 байт на каждый data-пакет.
**Маскировка**: не влияет (TLS record по-прежнему валиден, содержимое — случайные байты).

---

## Фаза 5: Plain ChaCha20 без Poly1305 (-16 байт, -40% CPU)

**Проблема**: ChaCha20-Poly1305 AEAD тратит ~40% вычислений на Poly1305 (authentication tag). Auth tag = 16 байт overhead.

**Решение**: `golang.org/x/crypto/chacha20.NewUnauthenticatedCipher(key, nonce)` — чистый XOR-stream cipher. AEAD сохранён для handshake (целостность).

- [x] Клиент: `EncryptInto` / `DecryptWithCounter` — plain ChaCha20 XOR
- [x] Сервер: `EncryptAndBuild` — plain ChaCha20 XOR
- [x] Сервер: `udpReadLoop` — plain ChaCha20 XOR
- [x] Handshake: AEAD сохранён (`Encrypt`/`Decrypt`/`DecryptWithNonce`)
- [x] Убрать `AuthTagSize` из расчётов data overhead
- [x] Скомпилировать оба

**Эффект**: -16 байт/пакет + ~40% ускорение крипто на data path.
**Маскировка**: не влияет (DPI видит те же случайные XOR-байты в TLS record).

---

## Фаза 6: 0-RTT session resumption

**Проблема**: при переподключении (смена WiFi, спящий режим) — полный handshake заново.

**Решение**: клиент сохраняет `sessionID + sessionKeys` при disconnect. При reconnect шлёт keepalive со старым sessionID. Сервер отвечает — сессия жива.

- [x] Клиент: `copySessionKeys()` + сохранение в `Disconnect()`
- [x] Клиент: `tryResume()` — отправка keepalive, 1 сек ожидание ответа
- [x] Клиент: `Connect()` — попытка resume перед handshake, fallback если не ответил
- [x] Сервер: `PacketDisconnect` — НЕ удалять сессию, держать до timeout
- [x] Сервер: `PacketKeepalive` — address migration (обновить ClientAddr)
- [x] Скомпилировать оба

**Эффект**: reconnect за **0 RTT** (мгновенный).
**Маскировка**: не влияет.

---

## Фаза 7: Параллельная настройка сети

**Проблема**: `Connect()` выполняет последовательно: handshake → TUN config → маршруты → старт loops.

**Решение**: DNS и маршруты запускаются параллельно. Data loops стартуют ДО настройки сети.

- [x] Клиент: `configureNetwork()` — DNS и маршруты в параллельных горутинах
- [x] Клиент: `Connect()` — loops стартуют до configureNetwork
- [x] Скомпилировать клиент

**Эффект**: ~100-200мс ускорение установки соединения.
**Маскировка**: не влияет.

---

## Сводка

| Фаза | Оптимизация | Скорость | Байт/пакет | Статус |
|------|-------------|----------|------------|--------|
| 1 | Counter-nonce | **+++** | 0 | ✅ Done |
| 2 | Убрать SetReadDeadline | **+** | 0 | ✅ Done |
| 3 | 1-RTT handshake | Connect **-0.5 RTT** | 0 | ✅ Done |
| 4 | Compact wire (counter) | **+** | **-8** | ✅ Done |
| 5 | Plain ChaCha20 | **++** | **-16** | ✅ Done |
| 6 | 0-RTT resumption | Reconnect **0 RTT** | 0 | ✅ Done |
| 7 | Параллельная настройка | Connect **-200мс** | 0 | ✅ Done |

**Итого data overhead**: TLS(5) + SID(4) + Type(1) + Counter(4) = **14 байт** (было 38 байт, -63%)
