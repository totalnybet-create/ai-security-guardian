#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

REPO="totalnybet-create/ai-security-guardian"
BRANCH="work/termux-agent"
PROJECT="$HOME/ai-security-guardian"
AGENT_HOME="$HOME/.local/share/guardian-agent"
STATE="$HOME/.local/state/guardian-agent"
SERVICE="$PREFIX/var/service/guardian-agent"

say() { printf '\n== %s ==\n' "$1"; }
fail() { printf '\nBŁĄD: %s\n' "$1" >&2; exit 1; }

ensure_command() {
  local cmd="$1" pkg_name="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    say "Instalacja brakującego pakietu: $pkg_name"
    pkg install -y "$pkg_name" || fail "Nie udało się zainstalować $pkg_name."
  fi
}

say "Precheck Termux"
[ -n "${PREFIX:-}" ] || fail "Brak środowiska Termux (PREFIX)."
ensure_command git git
ensure_command gh gh
ensure_command curl curl

mkdir -p "$AGENT_HOME" "$STATE/logs" "$STATE/artifacts" "$HOME/.local/bin"

say "Autoryzacja GitHub"
if ! gh auth status -h github.com >/dev/null 2>&1; then
  echo "GitHub poprosi jednorazowo o autoryzację tego Termuxa."
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

say "Instalacja agenta"
cp "$PROJECT/tools/termux-agent/guardian-agent.sh" "$AGENT_HOME/guardian-agent.sh"
chmod 700 "$AGENT_HOME/guardian-agent.sh"

# Prefer runit when termux-services is available, but do not make it a blocker.
if ! command -v sv >/dev/null 2>&1; then
  pkg install -y termux-services >/dev/null 2>&1 || true
fi

if command -v sv >/dev/null 2>&1; then
  mkdir -p "$SERVICE/log"
  cat > "$SERVICE/run" <<EOF_RUN
#!$PREFIX/bin/sh
export HOME="$HOME"
export PREFIX="$PREFIX"
export PATH="$HOME/.local/bin:$PREFIX/bin:/system/bin"
exec "$AGENT_HOME/guardian-agent.sh"
EOF_RUN
  chmod 700 "$SERVICE/run"

  cat > "$SERVICE/log/run" <<EOF_LOG
#!$PREFIX/bin/sh
mkdir -p "$STATE/service-log"
exec svlogd -tt "$STATE/service-log"
EOF_LOG
  chmod 700 "$SERVICE/log/run"
  rm -f "$SERVICE/down"
fi

cat > "$HOME/.local/bin/guardian-agent-start" <<'CTL'
#!/data/data/com.termux/files/usr/bin/bash
set -u
AGENT="$HOME/.local/share/guardian-agent/guardian-agent.sh"
STATE="$HOME/.local/state/guardian-agent"
SERVICE="$PREFIX/var/service/guardian-agent"
PIDFILE="$STATE/guardian-agent.pid"
mkdir -p "$STATE"

if command -v sv >/dev/null 2>&1 && [ -d "$SERVICE" ]; then
  if [ -f "$PREFIX/etc/profile.d/start-services.sh" ]; then
    . "$PREFIX/etc/profile.d/start-services.sh" >/dev/null 2>&1 || true
  fi
  rm -f "$SERVICE/down"
  sv up guardian-agent >/dev/null 2>&1 || sv up "$SERVICE" >/dev/null 2>&1 || true
  exit 0
fi

if [ -s "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" >/dev/null 2>&1; then
  exit 0
fi

nohup "$AGENT" >>"$STATE/nohup.log" 2>&1 &
echo $! > "$PIDFILE"
CTL

cat > "$HOME/.local/bin/guardian-agent-stop" <<'CTL'
#!/data/data/com.termux/files/usr/bin/bash
set -u
STATE="$HOME/.local/state/guardian-agent"
SERVICE="$PREFIX/var/service/guardian-agent"
PIDFILE="$STATE/guardian-agent.pid"

if command -v sv >/dev/null 2>&1 && [ -d "$SERVICE" ]; then
  sv down guardian-agent >/dev/null 2>&1 || sv down "$SERVICE" >/dev/null 2>&1 || true
fi

if [ -s "$PIDFILE" ]; then
  pid="$(cat "$PIDFILE")"
  kill "$pid" >/dev/null 2>&1 || true
  rm -f "$PIDFILE"
fi
CTL

cat > "$HOME/.local/bin/guardian-agent-status" <<'CTL'
#!/data/data/com.termux/files/usr/bin/bash
set -u
STATE="$HOME/.local/state/guardian-agent"
SERVICE="$PREFIX/var/service/guardian-agent"
PIDFILE="$STATE/guardian-agent.pid"

if command -v sv >/dev/null 2>&1 && [ -d "$SERVICE" ]; then
  sv status guardian-agent 2>/dev/null || sv status "$SERVICE" 2>/dev/null || true
elif [ -s "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" >/dev/null 2>&1; then
  echo "run: guardian-agent: (pid $(cat "$PIDFILE"))"
else
  echo "down: guardian-agent"
fi

printf '\nOstatnie wpisy:\n'
tail -n 30 "$STATE/agent.log" 2>/dev/null || true
CTL

chmod 700 \
  "$HOME/.local/bin/guardian-agent-start" \
  "$HOME/.local/bin/guardian-agent-stop" \
  "$HOME/.local/bin/guardian-agent-status"

MARKER="# guardian-agent-autostart"
if ! grep -qF "$MARKER" "$HOME/.bashrc" 2>/dev/null; then
  cat >> "$HOME/.bashrc" <<'BASHRC'
# guardian-agent-autostart
export PATH="$HOME/.local/bin:$PATH"
guardian-agent-start >/dev/null 2>&1 || true
BASHRC
fi

export PATH="$HOME/.local/bin:$PATH"
if command -v termux-wake-lock >/dev/null 2>&1; then
  termux-wake-lock >/dev/null 2>&1 || true
fi
guardian-agent-start

say "Weryfikacja"
gh auth status -h github.com
git -C "$PROJECT" rev-parse --short HEAD
guardian-agent-status
printf '\nAgent: %s\n' "$AGENT_HOME/guardian-agent.sh"
printf 'Log:   %s\n' "$STATE/agent.log"
printf 'Repo:  %s (%s)\n' "$PROJECT" "$BRANCH"
printf '\nGOTOWE. Telefon wykonuje tylko lekkiego agenta; testy i build APK są wykonywane na GitHub Actions.\n'
