#!/data/data/com.termux/files/usr/bin/bash
set -u

REPO="totalnybet-create/ai-security-guardian"
OWNER="totalnybet-create"
PROJECT="$HOME/ai-security-guardian"
BRANCH="work/termux-agent"
AGENT_HOME="$HOME/.local/share/guardian-agent"
STATE="$HOME/.local/state/guardian-agent"
LOGDIR="$STATE/logs"
ARTIFACT_DIR="$STATE/artifacts"
POLL_SECONDS="${GUARDIAN_AGENT_POLL_SECONDS:-30}"
WORKFLOW="android-ci.yml"

export PATH="$HOME/.local/bin:$PREFIX/bin:/system/bin:$PATH"
export GH_PAGER=cat

mkdir -p "$LOGDIR" "$ARTIFACT_DIR"

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$STATE/agent.log"
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
  echo "build_backend=github-actions"
  echo "workflow=$WORKFLOW"
  echo "gh=$(gh --version 2>/dev/null | head -n1 || true)"
  if [ -d "$PROJECT/.git" ]; then
    echo "commit=$(git -C "$PROJECT" rev-parse --short HEAD 2>/dev/null || true)"
    echo "dirty_nonlocal=$(test -n "$(cd "$PROJECT" && repo_dirty_nonlocal)" && echo yes || echo no)"
  fi
  df -h "$HOME" | tail -n1
}

latest_branch_run_id() {
  gh run list \
    --repo "$REPO" \
    --workflow "$WORKFLOW" \
    --branch "$BRANCH" \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId // empty'
}

remote_ci() {
  local before after tries
  before="$(latest_branch_run_id 2>/dev/null || true)"

  gh workflow run "$WORKFLOW" --repo "$REPO" --ref "$BRANCH"

  after=""
  tries=0
  while [ "$tries" -lt 30 ]; do
    sleep 2
    after="$(latest_branch_run_id 2>/dev/null || true)"
    if [ -n "$after" ] && [ "$after" != "$before" ]; then
      break
    fi
    tries=$((tries + 1))
  done

  [ -n "$after" ] || {
    echo "Nie udało się ustalić ID uruchomienia GitHub Actions."
    return 1
  }

  echo "github_run_id=$after"
  gh run watch "$after" --repo "$REPO" --exit-status
  gh run view "$after" --repo "$REPO" --json status,conclusion,url,headSha \
    --jq '"status=\(.status) conclusion=\(.conclusion) sha=\(.headSha) url=\(.url)"'
  printf '%s\n' "$after"
}

download_apk_from_run() {
  local run_id="$1" out apk download_dir
  download_dir="$ARTIFACT_DIR/$run_id"
  rm -rf "$download_dir"
  mkdir -p "$download_dir"

  gh run download "$run_id" \
    --repo "$REPO" \
    --name ai-security-guardian-debug-apk \
    --dir "$download_dir"

  apk="$(find "$download_dir" -type f -name '*.apk' | head -n1)"
  [ -n "$apk" ] || {
    echo "GitHub Actions zakończył się bez artefaktu APK."
    return 1
  }

  if [ -d "$HOME/storage/downloads" ]; then
    out="$HOME/storage/downloads/AI-Security-Guardian-debug.apk"
  else
    out="$HOME/AI-Security-Guardian-debug.apk"
  fi
  cp -f "$apk" "$out"
  echo "apk=$out"
  printf '%s\n' "$out"
}

action_remote_build() {
  local run_id
  run_id="$(remote_ci | tee /dev/stderr | tail -n1)" || return $?
  [ -n "$run_id" ] || return 1
  download_apk_from_run "$run_id" >/dev/null
  echo "build=success"
  echo "run_id=$run_id"
}

action_remote_build_open() {
  local run_id apk
  run_id="$(remote_ci | tee /dev/stderr | tail -n1)" || return $?
  [ -n "$run_id" ] || return 1
  apk="$(download_apk_from_run "$run_id" | tail -n1)" || return $?
  echo "apk=$apk"
  if command -v termux-open >/dev/null 2>&1; then
    termux-open "$apk"
  else
    echo "termux-open niedostępny; APK zapisany powyżej."
  fi
}

run_action() {
  case "$1" in
    ping) echo "PONG $(date -Iseconds)" ;;
    status) action_status ;;
    sync) action_sync ;;
    agent_update) action_agent_update ;;
    test|build|build_test) action_remote_build ;;
    build_open) action_remote_build_open ;;
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
  log "agent-start poll=${POLL_SECONDS}s build_backend=github-actions"
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
