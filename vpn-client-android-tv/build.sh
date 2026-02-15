#!/bin/bash
# =============================================================================
# NovaVPN Android TV — Скрипт сборки
# =============================================================================
#
# Использование:
#   ./build.sh           — Debug-сборка
#   ./build.sh release   — Release-сборка
#
# Требования:
#   - Android SDK (ANDROID_HOME или ANDROID_SDK_ROOT)
#   - JDK 17+
#   - Gradle 8.5+
#
# Результат:
#   dist/novavpn.apk
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Читаем версию из единого файла VERSION
VERSION_FILE="$SCRIPT_DIR/../VERSION"
if [ -f "$VERSION_FILE" ]; then
    APP_VERSION=$(cat "$VERSION_FILE" | tr -d '\r\n ')
else
    APP_VERSION="dev"
    echo "⚠️  Файл VERSION не найден, используем 'dev'"
fi

BUILD_TYPE="${1:-debug}"
DIST_DIR="$SCRIPT_DIR/dist"

echo "============================================"
echo "  NovaVPN Android TV v$APP_VERSION — Сборка ($BUILD_TYPE)"
echo "============================================"

# Проверяем наличие Android SDK
if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
    echo "❌ ANDROID_HOME или ANDROID_SDK_ROOT не установлен"
    echo ""
    echo "Установите Android SDK и задайте переменную окружения:"
    echo "  export ANDROID_HOME=~/Android/Sdk"
    echo ""
    echo "Или соберите проект в Android Studio:"
    echo "  1. Откройте папку vpn-client-android-tv в Android Studio"
    echo "  2. Build → Build Bundle(s) / APK(s) → Build APK(s)"
    exit 1
fi

echo "📦 Очистка..."
./gradlew clean 2>/dev/null || true

if [ "$BUILD_TYPE" = "release" ]; then
    echo "🔧 Release-сборка..."
    ./gradlew assembleRelease
    APK_PATH="app/build/outputs/apk/release/app-release.apk"
else
    echo "🔧 Debug-сборка..."
    ./gradlew assembleDebug
    APK_PATH="app/build/outputs/apk/debug/app-debug.apk"
fi

if [ ! -f "$APK_PATH" ]; then
    echo "❌ APK не найден: $APK_PATH"
    exit 1
fi

# Копируем в dist/ с нормальным именем
mkdir -p "$DIST_DIR"
APK_NAME="NovaVPN-AndroidTV-v${APP_VERSION}.apk"
cp "$APK_PATH" "$DIST_DIR/$APK_NAME"

echo ""
echo "============================================"
echo "  ✅ Сборка завершена! (v$APP_VERSION)"
echo "============================================"
echo ""
echo "  APK: $DIST_DIR/$APK_NAME"
echo "  Размер: $(du -h "$DIST_DIR/$APK_NAME" | cut -f1)"
echo ""
echo "  Установка на Android TV:"
echo "    adb install -r $DIST_DIR/$APK_NAME"
echo ""
