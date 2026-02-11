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

echo [1/4] Загружаем зависимости...
go mod tidy
if errorlevel 1 (
    echo [ОШИБКА] go mod tidy не удалось
    pause
    exit /b 1
)

echo [2/4] Встраиваем манифест...
cd cmd\novavpn
rsrc -manifest NovaVPN.exe.manifest -o rsrc.syso 2>nul
if errorlevel 1 (
    echo [WARN] rsrc не удалось, продолжаем без манифеста
)
cd ..\..\n
echo [3/4] Собираем NovaVPN.exe (GUI)...
go build -ldflags="-s -w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/
if errorlevel 1 (
    echo [ОШИБКА] Сборка GUI не удалась
    pause
    exit /b 1
)

echo [4/4] Собираем novavpn-service.exe (сервис)...
go build -ldflags="-s -w" -o novavpn-service.exe ./cmd/novavpn-service/
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
pause
