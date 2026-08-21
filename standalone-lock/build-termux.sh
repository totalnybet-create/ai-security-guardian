#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$PROJECT/build"
CACHE="$HOME/.cache/siedlar-one-tap-lock"
ANDROID_PLATFORM_ZIP="$CACHE/platform-36_r02.zip"
ANDROID_JAR="$CACHE/android-36/android.jar"
APK="$BUILD/Zablokuj-telefon.apk"
KEYSTORE="$CACHE/debug.keystore"
EXPECTED_SHA1="2c1a80dd4d9f7d0e6dd336ec603d9b5c55a6f576"

say() { printf '\n== %s ==\n' "$1"; }
fail() { printf '\nBŁĄD: %s\n' "$1" >&2; exit 1; }

say "Narzędzia"
pkg install -y openjdk-21 aapt2 apksigner zipalign zip unzip curl d8 >/dev/null
for cmd in java javac jar keytool aapt2 d8 zip zipalign apksigner curl unzip sha1sum; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Brak narzędzia: $cmd"
done

mkdir -p "$CACHE" "$BUILD/classes" "$BUILD/dex"
rm -rf "$BUILD/classes" "$BUILD/dex"
mkdir -p "$BUILD/classes" "$BUILD/dex"

if [ ! -s "$ANDROID_JAR" ]; then
    say "Android SDK Platform 36"
    rm -f "$ANDROID_PLATFORM_ZIP"
    curl -fL --retry 3 --retry-delay 2 \
        "https://dl.google.com/android/repository/platform-36_r02.zip" \
        -o "$ANDROID_PLATFORM_ZIP"
    ACTUAL_SHA1="$(sha1sum "$ANDROID_PLATFORM_ZIP" | awk '{print $1}')"
    [ "$ACTUAL_SHA1" = "$EXPECTED_SHA1" ] || fail "Nieprawidłowa suma SHA-1 platformy Android SDK."
    rm -rf "$CACHE/android-36"
    TMP="$CACHE/platform-unpack"
    rm -rf "$TMP"
    mkdir -p "$TMP"
    unzip -q "$ANDROID_PLATFORM_ZIP" -d "$TMP"
    PLATFORM_DIR="$(find "$TMP" -type f -name android.jar -printf '%h\n' | head -n 1)"
    [ -n "$PLATFORM_DIR" ] || fail "Nie znaleziono android.jar w paczce SDK."
    mkdir -p "$CACHE/android-36"
    cp "$PLATFORM_DIR/android.jar" "$ANDROID_JAR"
    rm -rf "$TMP" "$ANDROID_PLATFORM_ZIP"
fi

say "Zasoby i manifest"
aapt2 compile --dir "$PROJECT/res" -o "$BUILD/resources.zip"
aapt2 link \
    -I "$ANDROID_JAR" \
    --manifest "$PROJECT/AndroidManifest.xml" \
    --min-sdk-version 23 \
    --target-sdk-version 36 \
    -o "$BUILD/base.apk" \
    "$BUILD/resources.zip"

say "Java"
find "$PROJECT/src" -name '*.java' -print0 | xargs -0 javac \
    -source 11 -target 11 \
    -classpath "$ANDROID_JAR" \
    -d "$BUILD/classes"
(cd "$BUILD/classes" && jar cf "$BUILD/classes.jar" .)

say "DEX"
d8 --release \
    --min-api 23 \
    --lib "$ANDROID_JAR" \
    --output "$BUILD/dex" \
    "$BUILD/classes.jar"

say "APK"
cp "$BUILD/base.apk" "$BUILD/unsigned.apk"
(cd "$BUILD/dex" && zip -q "$BUILD/unsigned.apk" classes.dex)
zipalign -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"

if [ ! -f "$KEYSTORE" ]; then
    say "Podpis"
    keytool -genkeypair \
        -keystore "$KEYSTORE" \
        -alias siedlar-lock \
        -storepass android \
        -keypass android \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=Siedlar One Tap Lock" >/dev/null 2>&1
fi

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-key-alias siedlar-lock \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$APK" \
    "$BUILD/aligned.apk"

apksigner verify --verbose "$APK" >/dev/null

say "GOTOWE"
printf 'APK: %s\n' "$APK"
printf 'Po instalacji uruchom „Zablokuj telefon” i zaakceptuj jednorazowo administratora urządzenia.\n'

if command -v termux-open >/dev/null 2>&1; then
    termux-open "$APK" || true
fi
