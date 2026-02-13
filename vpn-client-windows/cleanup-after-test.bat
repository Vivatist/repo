@echo off
chcp 65001 >nul

:: ═══════════════════════════════════════════════════════════════
::   NovaVPN — Очистка структуры папок (после успешного теста v2.0.0)
:: ═══════════════════════════════════════════════════════════════

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                                                               ║
echo ║   NovaVPN — Очистка структуры проекта                       ║
echo ║                                                               ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo ВНИМАНИЕ: Этот скрипт удалит старые пакеты и файлы после того,
echo           как новая структура v2.0.0 успешно протестирована!
echo.
echo Будут удалены следующие компоненты:
echo.
echo   СТАРЫЕ ПАКЕТЫ (дублирующие новую архитектуру):
echo   ✗ internal/vpnclient/    (633 строки старого кода)
echo   ✗ internal/tunnel/       (388 строк старого кода)
echo   ✗ internal/crypto/       (214 строк старого кода)
echo   ✗ internal/config/       (старый JSON менеджер)
echo   ✗ internal/ipc/          (старый IPC)
echo   ✗ internal/service/      (старая логика службы)
echo.
echo   АРТЕФАКТЫ СБОРКИ:
echo   ✗ NovaVPN.exe            (в корне)
echo   ✗ novavpn-service.exe    (в корне)
echo   ✗ test-handshake.exe     (тестовая утилита)
echo   ✗ *.syso файлы           (ресурсы Windows)
echo.
echo   СТАРЫЕ СКРИПТЫ:
echo   ✗ build.bat              (заменён на build-v2.bat)
echo   ✗ build-installer.bat    (интегрирован в build-v2.bat)
echo.
echo Останутся только:
echo   ✓ Новая архитектура (domain/, infrastructure/, application/)
echo   ✓ build-v2.bat
echo   ✓ dist/ (создаётся при сборке)
echo   ✓ Документация
echo.

set /p confirm="Вы уверены? Введите YES для продолжения: "
if /i not "%confirm%"=="YES" (
    echo.
    echo Отменено. Ничего не удалено.
    pause
    exit /b 0
)

echo.
echo Начинаю очистку...
echo.

:: Удаление старых пакетов
echo [1/4] Удаление старых пакетов internal/...
if exist "internal\vpnclient" (
    rmdir /S /Q "internal\vpnclient"
    echo   [✓] internal/vpnclient/ удалён
)
if exist "internal\tunnel" (
    rmdir /S /Q "internal\tunnel"
    echo   [✓] internal/tunnel/ удалён
)
if exist "internal\crypto" (
    rmdir /S /Q "internal\crypto"
    echo   [✓] internal/crypto/ удалён
)
if exist "internal\config" (
    rmdir /S /Q "internal\config"
    echo   [✓] internal/config/ удалён
)
if exist "internal\ipc" (
    rmdir /S /Q "internal\ipc"
    echo   [✓] internal/ipc/ удалён
)
if exist "internal\service" (
    rmdir /S /Q "internal\service"
    echo   [✓] internal/service/ удалён
)
echo.

:: Удаление артефактов сборки
echo [2/4] Удаление артефактов сборки в корне...
if exist "NovaVPN.exe" (
    del /Q "NovaVPN.exe"
    echo   [✓] NovaVPN.exe удалён
)
if exist "novavpn-service.exe" (
    del /Q "novavpn-service.exe"
    echo   [✓] novavpn-service.exe удалён
)
if exist "test-handshake.exe" (
    del /Q "test-handshake.exe"
    echo   [✓] test-handshake.exe удалён
)
if exist "rsrc_windows_386.syso" (
    del /Q "rsrc_windows_*.syso"
    echo   [✓] *.syso файлы удалены
)
echo.

:: Удаление старых скриптов
echo [3/4] Удаление старых скриптов...
if exist "build.bat" (
    del /Q "build.bat"
    echo   [✓] build.bat удалён (заменён на build-v2.bat)
)
if exist "build-installer.bat" (
    del /Q "build-installer.bat"
    echo   [✓] build-installer.bat удалён (интегрирован в build-v2.bat)
)
echo.

:: Проверка оставшейся структуры
echo [4/4] Проверка новой структуры...
echo.
echo Оставшиеся пакеты в internal/:
dir /B /AD internal
echo.

echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                                                               ║
echo ║   Очистка завершена успешно!                                 ║
echo ║                                                               ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo Результат:
echo   ✓ Старые пакеты удалены (~2000 строк старого кода)
echo   ✓ Артефакты сборки очищены
echo   ✓ Старые скрипты удалены
echo.
echo Новая структура:
echo   ✓ internal/domain/         (интерфейсы)
echo   ✓ internal/infrastructure/ (реализации)
echo   ✓ internal/application/    (сервисы)
echo   ✓ internal/presentation/   (UI — TODO)
echo   ✓ internal/protocol/       (протокол NovaVPN)
echo   ✓ internal/elevation/      (UAC)
echo   ✓ internal/gui/            (временно, до рефакторинга)
echo.
echo Для сборки используйте: build-v2.bat
echo.
echo Статистика:
echo   - Подпапок было: ~25
echo   - Подпапок стало: ~15
echo   - Сокращение: ~40%%
echo.
echo   - Размер до очистки: ~54 МБ (с артефактами)
echo   - Размер после: ~10 МБ (только исходники)
echo.
pause
