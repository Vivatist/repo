@echo off
chcp 65001 >nul
echo ═══════════════════════════════════════════
echo   NovaVPN — Сборка инсталлятора
echo ═══════════════════════════════════════════
echo.

:: Проверяем наличие скомпилированных файлов
if not exist "NovaVPN.exe" (
    echo [ОШИБКА] NovaVPN.exe не найден. Сначала запустите build.bat
    pause
    exit /b 1
)
if not exist "novavpn-service.exe" (
    echo [ОШИБКА] novavpn-service.exe не найден. Сначала запустите build.bat
    pause
    exit /b 1
)
if not exist "wintun.dll" (
    echo [ОШИБКА] wintun.dll не найден.
    echo   Скопируйте wintun.dll ^(amd64^) в корень проекта.
    echo   Скачать: https://www.wintun.net/
    pause
    exit /b 1
)
if not exist "..\assets\logo.ico" (
    echo [INFO] logo.ico не найден, генерируем иконки из assets\...
    go run ./cmd/icongen/
    if errorlevel 1 (
        echo [ОШИБКА] Генерация иконок не удалась. Запустите build.bat
        pause
        exit /b 1
    )
)

:: Ищем Inno Setup
set "ISCC="

:: Пользовательская установка (winget/по умолчанию)
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" (
    set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
)
:: Стандартные пути установки Inno Setup 6
if "%ISCC%"=="" if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)
if "%ISCC%"=="" if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
)

:: Проверяем в PATH
if "%ISCC%"=="" (
    where iscc >nul 2>&1
    if not errorlevel 1 (
        set "ISCC=iscc"
    )
)

if "%ISCC%"=="" (
    echo [ОШИБКА] Inno Setup 6 не найден.
    echo.
    echo   Установите Inno Setup 6 с https://jrsoftware.org/isdl.php
    echo   или через winget:
    echo     winget install JRSoftware.InnoSetup
    echo.
    pause
    exit /b 1
)

:: Создаём папку dist если нет
if not exist "dist" mkdir dist

echo [1/1] Собираем инсталлятор...
"%ISCC%" installer\novavpn.iss
if errorlevel 1 (
    echo [ОШИБКА] Сборка инсталлятора не удалась
    pause
    exit /b 1
)

echo.
echo ═══════════════════════════════════════════
echo   Готово!
echo   Инсталлятор: dist\NovaVPN-Setup-1.0.0.exe
echo ═══════════════════════════════════════════
echo.
pause
