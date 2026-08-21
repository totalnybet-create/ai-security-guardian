#!/data/data/com.termux/files/usr/bin/bash
set -u

REPO="totalnybet-create/ai-security-guardian"
OWNER="totalnybet-create"
PROJECT="$HOME/ai-security-guardian"
BRANCH="work/termux-agent"
AGENT_HOME="$HOME/.local/share/guardian-agent"
GRADLE="$HOME/.local/opt/gradle-8.13/bin/gradle"
STATE="$HOME/.local/state/guardian-agent"
LOGDIR="$STATE/logs"
POLL_SECONDS="${GUARDIAN_AGENT_POLL_SECONDS:-30}"

JAVA17="$PREFIX/lib/jvm/java-17-openjdk"
if [ -x "$JAVA17/bin/java" ]; then
  export JAVA_HOME="$JAVA17"
  export PATH="$JAVA_HOME/bin:$HOME/.local/bin:$HOME/.local/opt/gradle-8.13/bin:$PREFIX/bin:$PATH"
else
  export PATH="$HOME/.local/bin:$HOME/.local/opt/gradle-8.13/bin:$PREFIX/bin:$PATH"
fi

export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export GH_PAGER=cat
export GRADLE_OPTS="${GRADLE_OPTS:-} -Dorg.gradle.native=false -Dorg.gradle.vfs.watch=false"

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
    -Dorg.gradle.native=false \
    -Dorg.gradle.vfs.watch=false \
    -Dorg.gradle.jvmargs='-Xmx1536m -Dfile.encoding=UTF-8 -Dorg.gradle.native=false -Dorg.gradle.vfs.watch=false' \
    -Pandroid.aapt2FromMavenOverride="$PREFIX/bin/aapt2" \
    "$@"
}

repo_dirty_nonlocal() {
  git status --porcelain --untracked-files=all | grep -vE '^\?\? local\.properties$|^ M local\.properties$' || true
}

action_sync() {
  cd "$PROJECT" || return 1
  if [ -n "$(repo_dirty_nonlocal)" ]; then
    echo "Repo ma lokalne zmiany inne niż local.properties; sync przerwany."
    return 2
  fi
  git fetch origin "$BRANCH"
  git checkout "$BRANCH"
  git pull --ff-only origin "$BRANCH"
  git rev-parse --short HEAD
}

action_agent_update() {
  action_sync || return $?
  cp "$PROJECT/tools/termux-agent/guardian-agent.sh" "$AGENT_HOME/guardian-agent.sh"
  chmod 700 "$AGENT_HOME/guardian-agent.sh"
  echo "agent_updated=$(git -C "$PROJECT" rev-parse --short HEAD)"
}

action_status() {
  echo "guardian-agent=ok"
  echo "time=$(date -Iseconds)"
  echo "repo=$REPO"
  echo "branch=$BRANCH"
  echo "project=$PROJECT"
  echo "android_home=$ANDROID_HOME"
  echo "java_home=${JAVA_HOME:-system}"
  echo "java=$(java -version 2>&1 | head -n1)"
  echo "gradle=$($GRADLE --version 2>/dev/null | awk '/Gradle /{print $2; exit}')"
  echo "aapt2=$(aapt2 version 2>&1 | head -n1)"
  if [ -d "$PROJECT/.git" ]; then
    echo "commit=$(git -C "$PROJECT" rev-parse --short HEAD 2>/dev/null || true)"
    echo "dirty_nonlocal=$(test -n "$(cd "$PROJECT" && repo_dirty_nonlocal)" && echo yes || echo no)"
  fi
  df -h "$HOME" | tail -n1
}

run_action() {
  case "$1" in
    ping) echo "PONG $(date -Iseconds)" ;;
    status) action_status ;;
    sync) action_sync ;;
    agent_update) action_agent_update ;;
    test) gradle_guardian :core-security:test ;;
    build) gradle_guardian :app:assembleDebug ;;
    build_test) gradle_guardian :core-security:test :app:assembleDebug ;;
    build_open) gradle_guardian :app:assembleDebug && termux-open "$PROJECT/app/build/outputs/apk/debug/app-debug.apk" ;;
    launch) am start -n pl.siedlar.securityguardian/.MainActivity ;;
    lock) am start -n pl.siedlar.securityguardian/.LockNowActivity ;;
    *) echo "Odrzucono niedozwoloną akcję: $1"; return 64 ;;
  esac
}

process_issue() {
  local number="$1" title="$2" author="$3" body_b64="$4"
  local body action started logfile rc excerpt comment reject_body start_body

  [ "$author" = "$OWNER" ] || { log "skip #$number author=$author"; return 0; }
  body="$(printf '%s' "$body_b64" | base64 -d 2>/dev/null || true)"
  printf '%s\n' "$body" | grep -qx 'TERMUX_AGENT_V1' || { log "skip #$number invalid-marker"; return 0; }
  action="$(printf '%s\n' "$body" | sed -n 's/^ACTION=\([A-Za-z0-9_]*\)$/\1/p' | head -n1)"
  [ -n "$action" ] || { log "skip #$number missing-action"; return 0; }

  case "$action" in
    ping|status|sync|agent_update|test|build|build_test|build_open|launch|lock) ;;
    *)
      reject_body="$(printf 'GUARDIAN_AGENT_RESULT\nstatus=REJECTED\naction=%s\nreason=action_not_allowed\n' "$action")"
      gh issue comment "$number" --repo "$REPO" --body "$reject_body" >/dev/null 2>&1 || true
      gh issue close "$number" --repo "$REPO" >/dev/null 2>&1 || true
      return 0
      ;;
  esac

  started="$(date -Iseconds)"
  logfile="$LOGDIR/issue-${number}-${action}-$(date +%Y%m%d-%H%M%S).log"
  log "start #$number action=$action title=$title"
  start_body="$(printf 'GUARDIAN_AGENT_STARTED\naction=%s\ntime=%s\n' "$action" "$started")"
  gh issue comment "$number" --repo "$REPO" --body "$start_body" >/dev/null 2>&1 || true

  if run_action "$action" >"$logfile" 2>&1; then rc=0; else rc=$?; fi

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

  if [ "$action" = "agent_update" ] && [ "$rc" -eq 0 ]; then
    log "self-reexec"
    exec "$AGENT_HOME/guardian-agent.sh"
  fi
}

main_loop() {
  log "agent-start poll=${POLL_SECONDS}s java_home=${JAVA_HOME:-system}"
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
      gh issue list --repo "$REPO" --state open --limit 30 --json number,title,body,author \
        --jq '.[] | select(.title | startswith("[TERMUX]")) | [.number,.title,.author.login,(.body|@base64)] | @tsv' \
        2>>"$STATE/agent.log" || true
    )
    sleep "$POLL_SECONDS"
  done
}

main_loop
