# Дорожная карта разработки: NovaVPN для Android TV

## Версия 2.0.0

### ✅ Этап 1: Анализ и проектирование
- [x] Изучение протокола NovaVPN v3 (NOVAVPN_PROTOCOL.md)
- [x] Изучение логики взаимодействия клиент-сервер (CLIENT_SERVER_INTERACTION.md)
- [x] Анализ реализации Windows-клиента (Go + Walk GUI)
- [x] Выбор технологического стека: **Kotlin + Jetpack Compose for TV**
- [x] Проектирование чистой архитектуры (domain → data → service → ui)

### ✅ Этап 2: Доменный слой (domain)
- [x] Модель состояния подключения (`ConnectionState`)
- [x] Модель параметров подключения (`ConnectParams`)
- [x] Модель информации о подключении (`ConnectionInfo`)
- [x] Модель здоровья соединения (`ConnectionHealth`)
- [x] Модель результата рукопожатия (`HandshakeResult`)
- [x] Модель конфигурации (`VpnConfig`)
- [x] Интерфейс репозитория конфигурации (`ConfigRepository`)
- [x] Интерфейс VPN-клиента (`VpnClient`)

### ✅ Этап 3: Протокол (data/protocol)
- [x] QUIC Short Header маскировка (5 байт: Flags + Random×4)
- [x] XOR-обфускация заголовков (SessionID + Type + Counter, маска из HMAC-SHA256(PSK))
- [x] Маршалинг HandshakeInit (pubkey + timestamp + creds + HMAC)
- [x] Маршалинг HandshakeComplete (confirmHMAC)
- [x] Маршалинг credentials (email + password в LTV-формате)
- [x] Маршалинг Data-пакетов (SessionID + Type + Counter + Ciphertext)
- [x] Маршалинг Keepalive/Disconnect (50-160 байт с random padding)
- [x] Парсинг входящих пакетов (Data, Keepalive, Disconnect, HandshakeResp)
- [x] Двухфазная деобфускация входящих пакетов (SID+Type → Counter)
- [x] Data padding (выравнивание до 64 байт + random 0-32)
- [x] Парсинг HandshakeResp (SessionID, IP, DNS, MTU, PSK)

### ✅ Этап 4: Криптография (data/crypto)
- [x] ChaCha20-Poly1305 AEAD (шифрование/дешифрование handshake)
- [x] Plain ChaCha20 XOR (шифрование/дешифрование data-пакетов)
- [x] HMAC-SHA256 (аутентификация рукопожатия)
- [x] Counter-nonce схема: prefix(4) + counter(8) = 12 байт
- [x] Вывод nonce prefix из ключа: HMAC-SHA256(key, "nova-nonce-prefix")[:4]
- [x] Curve25519 ECDH (через BouncyCastle X25519)
- [x] HKDF-SHA256 (вывод сессионных ключей, info="novavpn-session-keys-v1")
- [x] Swap send/recv ключей (клиент ↔ сервер)
- [x] PSK кодирование/декодирование (hex)

### ✅ Этап 5: Рукопожатие (data/vpn)
- [x] Генерация ephemeral Curve25519 ключевой пары
- [x] Шифрование credentials PSK-ключом
- [x] Вычисление HMAC(PSK, pubkey + timestamp + encCreds)
- [x] Отправка HandshakeInit (SessionID=0)
- [x] Получение HandshakeResp
- [x] ECDH(clientPriv, serverPub) → sharedSecret
- [x] DeriveSessionKeys(sharedSecret, PSK) → SendKey, RecvKey, HMACKey
- [x] Дешифрование ответа ChaCha20-Poly1305
- [x] Сохранение PSK при bootstrap-подключении
- [x] Отправка HandshakeComplete (fire-and-forget, 1-RTT)
- [x] Fallback: saved PSK → zero PSK (bootstrap)

### ✅ Этап 6: VPN-клиент (data/vpn)
- [x] UDP Read Loop (приём и дешифрование пакетов)
- [x] TUN Read Loop (чтение IP-пакетов, шифрование, отправка)
- [x] Keepalive Loop (рандомизированный, 10-20 сек, анти-DPI)
- [x] Health Monitor (пассивный, 3-7 сек, пороги 35с/60с)
- [x] Автопереподключение (экспоненциальный backoff, до 60 попыток)
- [x] 0-RTT Resume (сохранение/восстановление сессии)
- [x] Отправка Disconnect-пакета
- [x] Атомарная статистика (bytesSent, bytesRecv, packetsSent, packetsRecv)
- [x] Reactive state (StateFlow для UI)

### ✅ Этап 7: Репозиторий конфигурации (data/repository)
- [x] DataStore Preferences для хранения настроек
- [x] Сохранение/загрузка: сервер, email, пароль, PSK, wasConnected
- [x] Обновление PSK (при bootstrap)
- [x] Флаг wasConnected (для автозапуска)

### ✅ Этап 8: Android VpnService (service)
- [x] Foreground Service с уведомлением
- [x] TUN-интерфейс через VpnService.Builder
- [x] Маршрутизация всего трафика через VPN (0.0.0.0/0)
- [x] addDisallowedApplication(packageName) — исключение приложения из VPN (предотвращение routing loop)
- [x] protect() сокета с проверкой результата
- [x] DNS-настройка
- [x] Обработка ACTION_CONNECT / ACTION_DISCONNECT
- [x] Singleton для доступа из UI
- [x] Автообновление уведомления при смене состояния

### ✅ Этап 9: Автозапуск (receiver)
- [x] BroadcastReceiver на BOOT_COMPLETED
- [x] Проверка wasConnected
- [x] Проверка VPN-разрешения
- [x] Автоматический запуск VPN при включении ТВ

### ✅ Этап 10: Пользовательский интерфейс (ui)
- [x] Jetpack Compose для TV
- [x] D-pad навигация (Enter/OK для кнопок, два режима ввода текста)
- [x] Лаконичный главный экран (щит + статус + кнопка)
- [x] Анимация пульсации статуса
- [x] Панель настроек (сервер, email, пароль) с валидацией и сохранением
- [x] Показ/скрытие пароля (toggle)
- [x] Цветовая индикация состояния (серый/жёлтый/зелёный)
- [x] Отображение версии приложения (BuildConfig.VERSION_NAME)
- [x] ViewModel + StateFlow (reactive UI) + observeVpnState()

### ✅ Этап 11: Сборка и дистрибуция
- [x] Gradle конфигурация (Kotlin 1.9 + Compose + TV)
- [x] AndroidManifest (VPN, TV, Boot, Notifications)
- [x] ProGuard правила
- [x] Иконки и баннер (vector drawable)
- [x] README и документация сборки

---

## Архитектура

```
com.novavpn.tv/
├── domain/                    # Доменный слой (чистые модели и интерфейсы)
│   ├── model/                 # ConnectionState, ConnectParams, HandshakeResult, VpnConfig...
│   ├── repository/            # ConfigRepository (интерфейс)
│   └── service/               # VpnClient (интерфейс)
├── data/                      # Слой данных (реализации)
│   ├── crypto/                # NovaCryptoSession, NovaKeyExchange
│   ├── protocol/              # NovaProtocol (маршалинг/парсинг пакетов)
│   ├── repository/            # DataStoreConfigRepository
│   └── vpn/                   # NovaVpnClientImpl, HandshakePerformer
├── service/                   # Android VpnService
│   └── NovaVpnService         # Foreground service + TUN
├── receiver/                  # BroadcastReceiver
│   └── BootReceiver           # Автозапуск при включении ТВ
└── ui/                        # Пользовательский интерфейс
    ├── MainActivity           # ComponentActivity + Compose
    ├── MainViewModel          # AndroidViewModel + StateFlow
    └── NovaVpnScreen          # Compose UI (TV-оптимизированный)
```

## Технологии

| Компонент        | Технология                        |
|-----------------|-----------------------------------|
| Язык            | Kotlin 1.9                        |
| UI Framework    | Jetpack Compose for TV            |
| Архитектура     | Clean Architecture + MVVM         |
| Криптография    | BouncyCastle (X25519, ChaCha20, HKDF) |
| Хранилище       | DataStore Preferences             |
| Параллелизм     | Kotlin Coroutines + Flow          |
| Сборка          | Gradle + Android Plugin 8.2       |
| Min SDK         | 21 (Android 5.0)                  |
| Target SDK      | 34 (Android 14)                   |
