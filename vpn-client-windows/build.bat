@echo off
chcp 65001 >nul
echo ═══════════════════════════════════════════
echo   NovaVPN Client — Сборка для Windows
echo ═══════════════════════════════════════════
echo.

:: Проверяем Go
where go >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Go не найден. Установите Go 1.21+ с https://go.dev/dl/
    pause
    exit /b 1
)

:: Проверяем rsrc для встраивания манифеста
where rsrc >nul 2>&1
if errorlevel 1 (
    echo [INFO] Устанавливаем rsrc для встраивания манифеста...
    go install github.com/akavel/rsrc@latest
)

:: Проверяем go-winres для встраивания ресурсов версии
where go-winres >nul 2>&1
if errorlevel 1 (
    echo [INFO] Устанавливаем go-winres для встраивания информации о версии...
    go install github.com/tc-hib/go-winres@latest
)

echo [1/6] Загружаем зависимости...
go mod tidy
if errorlevel 1 (
    echo [ОШИБКА] go mod tidy не удалось
    pause
    exit /b 1
)

echo [2/6] Генерируем иконки из SVG (assets/)...
go run ./cmd/icongen/
if errorlevel 1 (
    echo [ОШИБКА] Генерация иконок не удалась
    pause
    exit /b 1
)

echo [3/6] Ресурсы GUI (иконка + манифест + версия)...
go-winres make --in winres\gui.json --out cmd\novavpn\winres --product-version 1.0.0.0 --file-version 1.0.0.0 2>nul
if errorlevel 1 (
    echo [WARN] go-winres не удалось для GUI, продолжаем без ресурсов
)

echo [4/6] Ресурсы сервиса (манифест + версия)...
go-winres make --in winres\winres.json --out cmd\novavpn-service\winres --product-version 1.0.0.0 --file-version 1.0.0.0 2>nul
if errorlevel 1 (
    echo [WARN] go-winres не удалось для сервиса, продолжаем без ресурсов
)

echo [5/6] Собираем NovaVPN.exe (GUI)...
go build -trimpath -ldflags="-w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/
if errorlevel 1 (
    echo [ОШИБКА] Сборка GUI не удалась
    pause
    exit /b 1
)

echo [6/6] Собираем novavpn-service.exe (сервис)...
go build -trimpath -ldflags="-w" -o novavpn-service.exe ./cmd/novavpn-service/
if errorlevel 1 (
    echo [ОШИБКА] Сборка сервиса не удалась
    pause
    exit /b 1
)

echo.
echo ═══════════════════════════════════════════
echo   Готово! Файлы:
echo     - NovaVPN.exe          (GUI, без админ прав)
echo     - novavpn-service.exe  (Windows сервис)
echo ═══════════════════════════════════════════
echo.
echo   ВАЖНО: Положите wintun.dll рядом с novavpn-service.exe
echo   Скачайте: https://www.wintun.net/
echo.
echo   Запуск: NovaVPN.exe (НЕ требует прав администратора)
echo   При первом подключении будет предложено установить сервис (UAC)
echo.
echo   ПРИМЕЧАНИЕ: Если Windows Defender блокирует файлы, скачанные
echo   из интернета, щёлкните правой кнопкой по ZIP-архиву в Проводнике,
echo   выберите "Свойства" и нажмите "Разблокировать" перед распаковкой.
echo.
pause
