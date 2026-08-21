#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

REPO="totalnybet-create/ai-security-guardian"
BRANCH="work/termux-agent"
PROJECT="$HOME/ai-security-guardian"
AGENT_HOME="$HOME/.local/share/guardian-agent"
STATE="$HOME/.local/state/guardian-agent"
GRADLE_HOME="$HOME/.local/opt/gradle-8.13"
SDK="$HOME/android-sdk"
PLATFORM_ZIP="$HOME/.cache/guardian-agent/platform-36_r02.zip"
PLATFORM_SHA1="2c1a80dd4d9f7d0e6dd336ec603d9b5c55a6f576"
GRADLE_ZIP="$HOME/.cache/guardian-agent/gradle-8.13-bin.zip"
GRADLE_SHA_URL="https://services.gradle.org/distributions/gradle-8.13-bin.zip.sha256"
GRADLE_URL="https://services.gradle.org/distributions/gradle-8.13-bin.zip"
SERVICE="$PREFIX/var/service/guardian-agent"
JAVA_HOME_TERMUX="$PREFIX/lib/jvm/java-21-openjdk"

say() { printf '\n== %s ==\n' "$1"; }
fail() { printf '\nBŁĄD: %s\n' "$1" >&2; exit 1; }

say "Pakiety Termux"
pkg update -y
pkg install -y git gh jq curl unzip coreutils openjdk-21 aapt2 apksigner d8 termux-services

[ -x "$JAVA_HOME_TERMUX/bin/java" ] || fail "Brak działającego OpenJDK 21."

mkdir -p "$AGENT_HOME" "$STATE/logs" "$HOME/.cache/guardian-agent" "$HOME/.local/opt" "$SDK/platforms" "$SDK/build-tools"

say "Autoryzacja GitHub"
if ! gh auth status -h github.com >/dev/null 2>&1; then
  echo "Za chwilę GitHub poprosi jednorazowo o autoryzację tego Termuxa."
  gh auth login --hostname github.com --git-protocol https --web
fi
gh auth setup-git

gh repo view "$REPO" >/dev/null 2>&1 || fail "To konto GitHub nie ma dostępu do $REPO."

say "Repo Guardiana"
if [ -d "$PROJECT/.git" ]; then
  git -C "$PROJECT" fetch origin "$BRANCH"
  dirty="$(git -C "$PROJECT" status --porcelain --untracked-files=all | grep -vE '^\?\? local\.properties$|^ M local\.properties$' || true)"
  [ -z "$dirty" ] || fail "W $PROJECT są lokalne zmiany inne niż local.properties."
  git -C "$PROJECT" checkout "$BRANCH"
  git -C "$PROJECT" pull --ff-only origin "$BRANCH"
else
  rm -rf "$PROJECT"
  gh repo clone "$REPO" "$PROJECT"
  git -C "$PROJECT" checkout "$BRANCH"
fi

say "Gradle 8.13"
if [ ! -x "$GRADLE_HOME/bin/gradle" ]; then
  rm -rf "$GRADLE_HOME" "$GRADLE_ZIP"
  curl -fL --retry 3 "$GRADLE_URL" -o "$GRADLE_ZIP"
  expected="$(curl -fsSL "$GRADLE_SHA_URL" | tr -d '[:space:]')"
  actual="$(sha256sum "$GRADLE_ZIP" | awk '{print $1}')"
  [ -n "$expected" ] && [ "$actual" = "$expected" ] || fail "Checksum Gradle 8.13 nie zgadza się."
  unzip -q "$GRADLE_ZIP" -d "$HOME/.local/opt"
  rm -f "$GRADLE_ZIP"
fi

say "Android SDK Platform 36"
if [ ! -s "$SDK/platforms/android-36/android.jar" ]; then
  rm -f "$PLATFORM_ZIP"
  curl -fL --retry 3 "https://dl.google.com/android/repository/platform-36_r02.zip" -o "$PLATFORM_ZIP"
  actual_sha1="$(sha1sum "$PLATFORM_ZIP" | awk '{print $1}')"
  [ "$actual_sha1" = "$PLATFORM_SHA1" ] || fail "Checksum Android SDK Platform 36 nie zgadza się."
  tmp="$HOME/.cache/guardian-agent/platform-unpack"
  rm -rf "$tmp" "$SDK/platforms/android-36"
  mkdir -p "$tmp"
  unzip -q "$PLATFORM_ZIP" -d "$tmp"
  platform_dir="$(find "$tmp" -type f -name android.jar -printf '%h\n' | head -n1)"
  [ -n "$platform_dir" ] || fail "Nie znaleziono android.jar."
  cp -a "$platform_dir" "$SDK/platforms/android-36"
  rm -rf "$tmp" "$PLATFORM_ZIP"
fi

say "Android Build Tools dla Termuxa"
for v in 35.0.0 36.0.0; do
  dir="$SDK/build-tools/$v"
  mkdir -p "$dir"
  ln -sf "$PREFIX/bin/aapt2" "$dir/aapt2"
  ln -sf "$PREFIX/bin/apksigner" "$dir/apksigner"
  ln -sf "$PREFIX/bin/d8" "$dir/d8"
  if command -v zipalign >/dev/null 2>&1; then
    ln -sf "$(command -v zipalign)" "$dir/zipalign"
  fi
  cat > "$dir/source.properties" <<PROP
Pkg.Desc=Android SDK Build-Tools $v (Termux bridge)
Pkg.Revision=$v
PROP
done

cat > "$PROJECT/local.properties" <<PROP
sdk.dir=$SDK
PROP

say "Instalacja agenta"
cp "$PROJECT/tools/termux-agent/guardian-agent.sh" "$AGENT_HOME/guardian-agent.sh"
chmod 700 "$AGENT_HOME/guardian-agent.sh"
mkdir -p "$SERVICE/log"
cat > "$SERVICE/run" <<EOF_RUN
#!$PREFIX/bin/sh
export HOME="$HOME"
export PREFIX="$PREFIX"
export PATH="$JAVA_HOME_TERMUX/bin:$HOME/.local/opt/gradle-8.13/bin:$PREFIX/bin:/system/bin"
exec "$AGENT_HOME/guardian-agent.sh"
EOF_RUN
chmod 700 "$SERVICE/run"

cat > "$SERVICE/log/run" <<EOF_LOG
#!$PREFIX/bin/sh
mkdir -p "$STATE/service-log"
exec svlogd -tt "$STATE/service-log"
EOF_LOG
chmod 700 "$SERVICE/log/run"

if [ -f "$PREFIX/etc/profile.d/start-services.sh" ]; then
  . "$PREFIX/etc/profile.d/start-services.sh" || true
fi

rm -f "$SERVICE/down"
sv restart guardian-agent >/dev/null 2>&1 || sv restart "$SERVICE" >/dev/null 2>&1 || sv up "$SERVICE" >/dev/null 2>&1 || true

mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/guardian-agent-start" <<'CTL'
#!/data/data/com.termux/files/usr/bin/bash
sv up guardian-agent 2>/dev/null || sv up "$PREFIX/var/service/guardian-agent"
CTL
cat > "$HOME/.local/bin/guardian-agent-stop" <<'CTL'
#!/data/data/com.termux/files/usr/bin/bash
sv down guardian-agent 2>/dev/null || sv down "$PREFIX/var/service/guardian-agent"
CTL
cat > "$HOME/.local/bin/guardian-agent-status" <<'CTL'
#!/data/data/com.termux/files/usr/bin/bash
sv status guardian-agent 2>/dev/null || sv status "$PREFIX/var/service/guardian-agent" || true
printf '\nOstatnie wpisy:\n'
tail -n 30 "$HOME/.local/state/guardian-agent/agent.log" 2>/dev/null || true
CTL
chmod 700 "$HOME/.local/bin/guardian-agent-start" "$HOME/.local/bin/guardian-agent-stop" "$HOME/.local/bin/guardian-agent-status"

MARKER="# guardian-agent-autostart"
if ! grep -qF "$MARKER" "$HOME/.bashrc" 2>/dev/null; then
  cat >> "$HOME/.bashrc" <<'BASHRC'
# guardian-agent-autostart
export PATH="$HOME/.local/bin:$PATH"
if [ -f "$PREFIX/etc/profile.d/start-services.sh" ]; then
  . "$PREFIX/etc/profile.d/start-services.sh" >/dev/null 2>&1 || true
fi
BASHRC
fi

say "Weryfikacja"
"$JAVA_HOME_TERMUX/bin/java" -version 2>&1 | head -n2
aapt2 version 2>&1 | head -n1
gh auth status -h github.com
printf '\nAgent: %s\n' "$AGENT_HOME/guardian-agent.sh"
printf 'Log:   %s\n' "$STATE/agent.log"
printf 'Repo:  %s (%s)\n' "$PROJECT" "$BRANCH"
printf '\nGOTOWE. Agent używa JDK 21; test Gradle wykonamy zdalnie przez kolejkę.\n'
