# =============================================================================
# NovaVPN Android TV — Скрипт сборки (Windows)
# =============================================================================
#
# Использование:
#   .\build.ps1              — Debug-сборка
#   .\build.ps1 -release     — Release-сборка
#   .\build.ps1 -clean       — Очистка перед сборкой
#   .\build.ps1 -install     — Собрать и установить на устройство (adb)
#
# Требования:
#   - Android SDK (ANDROID_HOME или ANDROID_SDK_ROOT)
#   - JDK 17+
#   - Gradle wrapper (gradlew.bat) в проекте
#
# Результат:
#   dist\NovaVPN-AndroidTV-v{VERSION}.apk
# =============================================================================

param(
    [switch]$release,
    [switch]$clean,
    [switch]$install
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir

try {
    # --- Версия ---
    $versionFile = Join-Path $scriptDir "..\VERSION"
    if (Test-Path $versionFile) {
        $appVersion = (Get-Content $versionFile -Raw).Trim()
    } else {
        $appVersion = "dev"
        Write-Warning "Файл VERSION не найден, используем 'dev'"
    }

    $buildType = if ($release) { "release" } else { "debug" }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  NovaVPN Android TV v$appVersion — Сборка ($buildType)" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # --- Проверка Android SDK ---
    $sdk = $env:ANDROID_HOME
    if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
    if (-not $sdk) {
        # Проверяем стандартные пути
        $defaultPaths = @(
            "$env:LOCALAPPDATA\Android\Sdk",
            "$env:USERPROFILE\AppData\Local\Android\Sdk"
        )
        foreach ($p in $defaultPaths) {
            if (Test-Path $p) { $sdk = $p; break }
        }
    }
    if (-not $sdk -or -not (Test-Path $sdk)) {
        Write-Host "ANDROID_HOME или ANDROID_SDK_ROOT не установлен" -ForegroundColor Red
        Write-Host ""
        Write-Host "Установите Android SDK и задайте переменную окружения:" -ForegroundColor Yellow
        Write-Host '  $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"'
        Write-Host ""
        Write-Host "Или соберите проект в Android Studio:" -ForegroundColor Yellow
        Write-Host "  1. Откройте папку vpn-client-android-tv в Android Studio"
        Write-Host "  2. Build -> Build Bundle(s) / APK(s) -> Build APK(s)"
        exit 1
    }
    Write-Host "Android SDK: $sdk" -ForegroundColor DarkGray

    # --- Проверка / автоопределение JAVA_HOME ---
    if (-not $env:JAVA_HOME -or -not (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
        # Ищем JDK встроенный в Android Studio (jbr)
        $studioJbr = "C:\Program Files\Android\Android Studio\jbr"
        if (Test-Path "$studioJbr\bin\java.exe") {
            $env:JAVA_HOME = $studioJbr
            Write-Host "JAVA_HOME (Android Studio JBR): $studioJbr" -ForegroundColor DarkGray
        } else {
            Write-Host "JAVA_HOME не установлен и JDK не найден" -ForegroundColor Red
            Write-Host ""
            Write-Host "Установите JDK 17+ и задайте переменную окружения:" -ForegroundColor Yellow
            Write-Host '  $env:JAVA_HOME = "C:\Program Files\Java\jdk-17"'
            Write-Host ""
            Write-Host "Или установите Android Studio — его встроенный JDK будет использован автоматически." -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Host "JAVA_HOME: $env:JAVA_HOME" -ForegroundColor DarkGray
    }

    # --- Проверка gradlew.bat ---
    $gradlew = Join-Path $scriptDir "gradlew.bat"
    if (-not (Test-Path $gradlew)) {
        Write-Host "gradlew.bat не найден в $scriptDir" -ForegroundColor Red
        exit 1
    }

    # --- Очистка ---
    if ($clean) {
        Write-Host "Очистка..." -ForegroundColor Yellow
        & $gradlew clean
        if ($LASTEXITCODE -ne 0) { throw "Gradle clean завершился с ошибкой" }
    }

    # --- Сборка ---
    if ($release) {
        Write-Host "Release-сборка..." -ForegroundColor Yellow
        & $gradlew assembleRelease
        # Подписанный APK
        $apkPath = Join-Path $scriptDir "app\build\outputs\apk\release\app-release.apk"
    } else {
        Write-Host "Debug-сборка..." -ForegroundColor Yellow
        & $gradlew assembleDebug
        $apkPath = Join-Path $scriptDir "app\build\outputs\apk\debug\app-debug.apk"
    }

    if ($LASTEXITCODE -ne 0) { throw "Gradle сборка завершилась с ошибкой" }

    if (-not (Test-Path $apkPath)) {
        Write-Host "APK не найден: $apkPath" -ForegroundColor Red
        exit 1
    }

    # --- Копируем в dist\ ---
    $distDir = Join-Path $scriptDir "dist"
    if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

    $apkName = "NovaVPN-AndroidTV-v$appVersion.apk"
    $destPath = Join-Path $distDir $apkName
    Copy-Item $apkPath $destPath -Force

    $size = (Get-Item $destPath).Length
    $sizeMB = [math]::Round($size / 1MB, 1)

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  Сборка завершена! (v$appVersion)" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  APK: $destPath"
    Write-Host "  Размер: $sizeMB МБ"
    Write-Host ""

    # --- Установка на устройство ---
    if ($install) {
        $adb = Get-Command adb -ErrorAction SilentlyContinue
        if (-not $adb) {
            $adb = Join-Path $sdk "platform-tools\adb.exe"
            if (-not (Test-Path $adb)) {
                Write-Host "adb не найден. Установите Android SDK Platform-Tools." -ForegroundColor Red
                exit 1
            }
        } else {
            $adb = $adb.Source
        }

        Write-Host "Установка на устройство..." -ForegroundColor Yellow
        & $adb install -r $destPath
        if ($LASTEXITCODE -ne 0) { throw "adb install завершился с ошибкой" }
        Write-Host "APK установлен!" -ForegroundColor Green
    } else {
        Write-Host "  Установка на Android TV:"
        Write-Host "    adb install -r $destPath"
        Write-Host ""
    }

} finally {
    Pop-Location
}
