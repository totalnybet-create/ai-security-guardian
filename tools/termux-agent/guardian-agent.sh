#!/data/data/com.termux/files/usr/bin/bash
set -u

REPO="totalnybet-create/ai-security-guardian"
OWNER="totalnybet-create"
PROJECT="$HOME/ai-security-guardian"
BRANCH="work/termux-agent"
GRADLE="$HOME/.local/opt/gradle-8.13/bin/gradle"
STATE="$HOME/.local/state/guardian-agent"
LOGDIR="$STATE/logs"
POLL_SECONDS="${GUARDIAN_AGENT_POLL_SECONDS:-30}"
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export GH_PAGER=cat
export PATH="$HOME/.local/bin:$HOME/.local/opt/gradle-8.13/bin:$PREFIX/bin:$PATH"

mkdir -p "$LOGDIR"

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$STATE/agent.log"
}

gradle_guardian() {
  cd "$PROJECT" || return 1
  "$GRADLE" \
    --no-daemon \
    --stacktrace \
    --max-workers=2 \
    -Dorg.gradle.jvmargs='-Xmx1536m -Dfile.encoding=UTF-8' \
    -Pandroid.aapt2FromMavenOverride="$PREFIX/bin/aapt2" \
    "$@"
}

action_sync() {
  cd "$PROJECT" || return 1
  if [ -n "$(git status --porcelain)" ]; then
    echo "Repo ma lokalne zmiany; sync przerwany, żeby niczego nie nadpisać."
    return 2
  fi
  git fetch origin "$BRANCH"
  git checkout "$BRANCH"
  git pull --ff-only origin "$BRANCH"
  git rev-parse --short HEAD
}

action_status() {
  echo "guardian-agent=ok"
  echo "time=$(date -Iseconds)"
  echo "repo=$REPO"
  echo "branch=$BRANCH"
  echo "project=$PROJECT"
  echo "android_home=$ANDROID_HOME"
  echo "java=$(java -version 2>&1 | head -n1)"
  echo "gradle=$($GRADLE --version 2>/dev/null | awk '/Gradle /{print $2; exit}')"
  echo "aapt2=$(aapt2 version 2>&1 | head -n1)"
  if [ -d "$PROJECT/.git" ]; then
    echo "commit=$(git -C "$PROJECT" rev-parse --short HEAD 2>/dev/null || true)"
    echo "dirty=$(test -n "$(git -C "$PROJECT" status --porcelain 2>/dev/null)" && echo yes || echo no)"
  fi
  df -h "$HOME" | tail -n1
}

run_action() {
  case "$1" in
    ping)
      echo "PONG $(date -Iseconds)"
      ;;
    status)
      action_status
      ;;
    sync)
      action_sync
      ;;
    test)
      gradle_guardian :core-security:test
      ;;
    build)
      gradle_guardian :app:assembleDebug
      ;;
    build_test)
      gradle_guardian :core-security:test :app:assembleDebug
      ;;
    build_open)
      gradle_guardian :app:assembleDebug && termux-open "$PROJECT/app/build/outputs/apk/debug/app-debug.apk"
      ;;
    launch)
      am start -n pl.siedlar.securityguardian/.MainActivity
      ;;
    lock)
      am start -n pl.siedlar.securityguardian/.LockNowActivity
      ;;
    *)
      echo "Odrzucono niedozwoloną akcję: $1"
      return 64
      ;;
  esac
}

process_issue() {
  local number="$1"
  local title="$2"
  local author="$3"
  local body_b64="$4"
  local body action started logfile rc excerpt comment

  [ "$author" = "$OWNER" ] || { log "skip #$number author=$author"; return 0; }
  body="$(printf '%s' "$body_b64" | base64 -d 2>/dev/null || true)"
  printf '%s\n' "$body" | grep -qx 'TERMUX_AGENT_V1' || { log "skip #$number invalid-marker"; return 0; }
  action="$(printf '%s\n' "$body" | sed -n 's/^ACTION=\([A-Za-z0-9_]*\)$/\1/p' | head -n1)"
  [ -n "$action" ] || { log "skip #$number missing-action"; return 0; }

  case "$action" in
    ping|status|sync|test|build|build_test|build_open|launch|lock) ;;
    *)
      gh issue comment "$number" --repo "$REPO" --body "GUARDIAN_AGENT_RESULT\nstatus=REJECTED\naction=$action\nreason=action_not_allowed" >/dev/null 2>&1 || true
      gh issue close "$number" --repo "$REPO" >/dev/null 2>&1 || true
      return 0
      ;;
  esac

  started="$(date -Iseconds)"
  logfile="$LOGDIR/issue-${number}-${action}-$(date +%Y%m%d-%H%M%S).log"
  log "start #$number action=$action title=$title"

  gh issue comment "$number" --repo "$REPO" --body "GUARDIAN_AGENT_STARTED\naction=$action\ntime=$started" >/dev/null 2>&1 || true

  set +e
  run_action "$action" >"$logfile" 2>&1
  rc=$?
  set -e

  excerpt="$(tail -c 12000 "$logfile" 2>/dev/null || true)"
  comment="$STATE/comment-$number.txt"
  {
    echo 'GUARDIAN_AGENT_RESULT'
    echo "action=$action"
    echo "exit_code=$rc"
    echo "started=$started"
    echo "finished=$(date -Iseconds)"
    echo
    echo '```text'
    printf '%s\n' "$excerpt"
    echo '```'
  } > "$comment"

  gh issue comment "$number" --repo "$REPO" --body-file "$comment" >/dev/null 2>&1 || true
  gh issue close "$number" --repo "$REPO" >/dev/null 2>&1 || true
  rm -f "$comment"
  log "finish #$number action=$action rc=$rc"
}

main_loop() {
  log "agent-start poll=${POLL_SECONDS}s"
  while true; do
    if ! gh auth status -h github.com >/dev/null 2>&1; then
      log "github-auth-missing"
      sleep "$POLL_SECONDS"
      continue
    fi

    while IFS=$'\t' read -r number title author body_b64; do
      [ -n "${number:-}" ] || continue
      process_issue "$number" "$title" "$author" "$body_b64"
    done < <(
      gh issue list \
        --repo "$REPO" \
        --state open \
        --limit 30 \
        --json number,title,body,author \
        --jq '.[] | select(.title | startswith("[TERMUX]")) | [.number,.title,.author.login,(.body|@base64)] | @tsv' \
        2>>"$STATE/agent.log" || true
    )

    sleep "$POLL_SECONDS"
  done
}

main_loop
