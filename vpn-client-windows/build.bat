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

echo [1/3] Загружаем зависимости...
go mod tidy
if errorlevel 1 (
    echo [ОШИБКА] go mod tidy не удалось
    pause
    exit /b 1
)

echo [2/3] Встраиваем манифест...
cd cmd\novavpn
rsrc -manifest NovaVPN.exe.manifest -o rsrc.syso 2>nul
if errorlevel 1 (
    echo [WARN] rsrc не удалось, продолжаем без манифеста
)
cd ..\..

echo [3/3] Собираем NovaVPN.exe...
go build -ldflags="-s -w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/
if errorlevel 1 (
    echo [ОШИБКА] Сборка не удалась
    pause
    exit /b 1
)

echo.
echo ═══════════════════════════════════════════
echo   Готово! Файл: NovaVPN.exe
echo ═══════════════════════════════════════════
echo.
echo   ВАЖНО: Положите wintun.dll рядом с NovaVPN.exe
echo   Скачайте: https://www.wintun.net/
echo.
echo   Запуск: NovaVPN.exe (от имени администратора)
echo.
pause
