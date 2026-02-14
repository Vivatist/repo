@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: Переходим в корень проекта (vpn-client-windows)
cd /d "%~dp0.."

:: ═══════════════════════════════════════════════════════════════
::   NovaVPN Client v2.0.0 — Полная сборка и инсталлятор
:: ═══════════════════════════════════════════════════════════════

set VERSION=2.0.0
set APP_NAME=NovaVPN

:: Принудительно устанавливаем целевую платформу Windows
:: (сбрасывает GOOS=linux, если остался от сборки сервера)
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                                                               ║
echo ║   %APP_NAME% Client v%VERSION% — Сборка для Windows         ║
echo ║                                                               ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 1: Проверка зависимостей
:: ═══════════════════════════════════════════════════════════════

echo [ШАГ 1/8] Проверка зависимостей...
echo.

:: Проверяем Go
where go >nul 2>&1
if errorlevel 1 (
    echo [✗] Go не найден
    echo     Установите Go 1.21+ с https://go.dev/dl/
    echo.
    pause
    exit /b 1
)
for /f "tokens=3" %%a in ('go version 2^>nul') do set GO_VERSION=%%a
echo [✓] Go найден: %GO_VERSION%

:: Проверяем и устанавливаем go-winres
where go-winres >nul 2>&1
if errorlevel 1 (
    echo [→] Устанавливаем go-winres для встраивания ресурсов...
    go install github.com/tc-hib/go-winres@latest
    if errorlevel 1 (
        echo [✗] Не удалось установить go-winres
        pause
        exit /b 1
    )
    echo [✓] go-winres установлен
) else (
    echo [✓] go-winres найден
)

:: Проверяем Inno Setup для инсталлятора
set "ISCC="
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" (
    set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
)
if "%ISCC%"=="" if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)
if "%ISCC%"=="" if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
)
if "%ISCC%"=="" (
    where iscc >nul 2>&1
    if not errorlevel 1 (
        set "ISCC=iscc"
    )
)

if "%ISCC%"=="" (
    echo [✗] Inno Setup 6 не найден
    echo     Установите с https://jrsoftware.org/isdl.php
    echo     или через: winget install JRSoftware.InnoSetup
    echo.
    echo [!] Сборка продолжится без создания инсталлятора
    echo.
    set CREATE_INSTALLER=0
) else (
    echo [✓] Inno Setup найден
    set CREATE_INSTALLER=1
)

:: Проверяем наличие wintun.dll
if exist "wintun\wintun\bin\amd64\wintun.dll" (
    echo [✓] wintun.dll найден в wintun\wintun\bin\amd64\
    set HAS_WINTUN=1
) else (
    echo [!] wintun.dll не найден
    echo     Скачайте с https://www.wintun.net/ ^(amd64^)
    echo     Положите в wintun\wintun\bin\amd64\
    echo.
    echo [!] Сборка продолжится, но для работы потребуется wintun.dll
    echo.
    set HAS_WINTUN=0
)

echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 2: Загрузка зависимостей Go
:: ═══════════════════════════════════════════════════════════════

echo.
echo [ШАГ 2/8] Загрузка зависимостей Go...
go mod tidy
if errorlevel 1 (
    echo [✗] Не удалось выполнить go mod tidy
    pause
    exit /b 1
)
echo [✓] Зависимости загружены
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 3: Генерация иконок
:: ═══════════════════════════════════════════════════════════════

echo [ШАГ 3/8] Генерация иконок из SVG...
go run ./cmd/icongen/
if errorlevel 1 (
    echo [!] Генерация иконок не удалась (продолжаем)
) else (
    echo [✓] Иконки сгенерированы
)
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 4: Встраивание ресурсов Windows (GUI)
:: ═══════════════════════════════════════════════════════════════

echo [ШАГ 4/8] Встраивание ресурсов для GUI (иконка, манифест, версия)...
go-winres make --in winres\gui.json --out cmd\novavpn\winres --product-version %VERSION%.0 --file-version %VERSION%.0 2>nul
if errorlevel 1 (
    echo [!] go-winres не удалось (продолжаем без ресурсов)
) else (
    echo [✓] Ресурсы GUI встроены (версия %VERSION%)
)
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 5: Встраивание ресурсов Windows (Service)
:: ═══════════════════════════════════════════════════════════════

echo [ШАГ 5/8] Встраивание ресурсов для Service (манифест, версия)...
go-winres make --in winres\winres.json --out cmd\novavpn-service\winres --product-version %VERSION%.0 --file-version %VERSION%.0 2>nul
if errorlevel 1 (
    echo [!] go-winres не удалось (продолжаем без ресурсов)
) else (
    echo [✓] Ресурсы Service встроены (версия %VERSION%)
)
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 6: Компиляция
:: ═══════════════════════════════════════════════════════════════

echo [ШАГ 6/8] Компиляция приложений...
echo.

:: Создаём папку дистрибутива заранее (для -o)
if not exist "dist" mkdir dist
if not exist "dist\NovaVPN" mkdir dist\NovaVPN

echo   [6.1] Сборка NovaVPN.exe (GUI)...
go build -trimpath -ldflags="-s -w -H windowsgui" -o dist\NovaVPN\NovaVPN.exe ./cmd/novavpn/
if errorlevel 1 (
    echo   [✗] Ошибка сборки GUI
    pause
    exit /b 1
)
echo   [✓] NovaVPN.exe создан

echo   [6.2] Сборка novavpn-service.exe (Service)...
go build -trimpath -ldflags="-s -w" -o dist\NovaVPN\novavpn-service.exe ./cmd/novavpn-service/
if errorlevel 1 (
    echo   [✗] Ошибка сборки Service
    pause
    exit /b 1
)
echo   [✓] novavpn-service.exe создан

echo.
echo [✓] Компиляция завершена
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 7: Подготовка дистрибутива
:: ═══════════════════════════════════════════════════════════════

echo [ШАГ 7/8] Подготовка дистрибутива...
echo.

if %HAS_WINTUN%==1 (
    copy /Y "wintun\wintun\bin\amd64\wintun.dll" dist\NovaVPN\ >nul
    echo   [✓] wintun.dll скопирован в dist\NovaVPN\
) else (
    echo   [!] wintun.dll отсутствует — добавьте вручную
)

:: Создаём README для дистрибутива
echo Создание README.txt...
(
echo NovaVPN v%VERSION%
echo.
echo Файлы:
echo   - NovaVPN.exe          GUI приложение
echo   - novavpn-service.exe  Windows служба
echo   - wintun.dll           WinTUN драйвер
echo.
echo Установка:
echo   1. Запустите NovaVPN.exe
echo   2. При первом подключении будет предложено установить службу
echo   3. Введите данные сервера и подключитесь
echo.
echo ВАЖНО: Для работы требуется wintun.dll в той же папке!
echo        Скачайте с https://www.wintun.net/ если отсутствует
echo.
echo Документация: https://github.com/Vivatist/repo
) > dist\NovaVPN\README.txt
echo   [✓] README.txt создан

echo.
echo [✓] Дистрибутив подготовлен в dist\NovaVPN\
echo.

:: ═══════════════════════════════════════════════════════════════
::   ШАГ 8: Создание инсталлятора
:: ═══════════════════════════════════════════════════════════════

if %CREATE_INSTALLER%==0 (
    echo [ШАГ 8/8] Создание инсталлятора... ПРОПУЩЕНО
    echo   Inno Setup не найден
    goto :summary
)

echo [ШАГ 8/8] Создание инсталлятора...
echo.
echo   [→] Запуск Inno Setup Compiler...
"%ISCC%" installer\novavpn.iss
if errorlevel 1 (
    echo   [✗] Ошибка создания инсталлятора
    echo.
    pause
    exit /b 1
)
echo.
echo   [✓] Инсталлятор создан: dist\NovaVPN-Setup-%VERSION%.exe
echo.

:: ═══════════════════════════════════════════════════════════════
::   Итоговая информация
:: ═══════════════════════════════════════════════════════════════

:summary
echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                                                               ║
echo ║   Сборка завершена успешно!                                  ║
echo ║                                                               ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo Созданные файлы:
echo.
echo   В корне:
echo     ✓ NovaVPN.exe          (GUI, %~z0 байт)
echo     ✓ novavpn-service.exe  (Служба)
echo.
echo   В dist\NovaVPN\:
echo     ✓ NovaVPN.exe
echo     ✓ novavpn-service.exe
if %HAS_WINTUN%==1 (
    echo     ✓ wintun.dll
) else (
    echo     ✗ wintun.dll (отсутствует — добавьте вручную!)
)
echo     ✓ README.txt
echo.

if %CREATE_INSTALLER%==1 (
    echo   Инсталлятор:
    echo     ✓ dist\NovaVPN-Setup-%VERSION%.exe
    echo.
)

echo.
echo ┌───────────────────────────────────────────────────────────────┐
echo │ Следующие шаги:                                               │
echo │                                                               │
if %HAS_WINTUN%==0 (
    echo │ 1. Скачайте wintun.dll с https://www.wintun.net/                │
    echo │    и положите в dist\NovaVPN\                                   │
    echo │                                                                 │
)
if %CREATE_INSTALLER%==1 (
    echo │ 2. Запустите инсталлятор:                                     │
    echo │    dist\NovaVPN-Setup-%VERSION%.exe                               │
) else (
    echo │ 2. Скопируйте папку dist\NovaVPN\ на целевой компьютер          │
    echo │    и запустите NovaVPN.exe                                      │
)
echo │                                                               │
echo │ 3. Протестируйте подключение к серверу                        │
echo │                                                               │
echo └───────────────────────────────────────────────────────────────┘
echo.

if %HAS_WINTUN%==0 (
    echo [!] НЕ ЗАБУДЬТЕ: Приложению требуется wintun.dll для работы!
    echo.
)

