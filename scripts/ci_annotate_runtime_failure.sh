#!/usr/bin/env bash
# Publishes WHY a real-LLM runtime step failed as one error annotation. Job logs and artifacts are not always readable
# from outside the runner, annotations are (REST: check-runs/<id>/annotations), so a red job says what happened.
# Usage: ci_annotate_runtime_failure.sh <exit-status> <title> [step-stderr-file]
# Collects, in this order: the tail of Ollama's own log (model load, timeouts), the tail of the OLA container log (the
# application traceback is there) and the tail of the failed step's stderr. Never fails by itself: the step keeps its
# own exit status.
set -u
rc="${1:?usage: ci_annotate_runtime_failure.sh <exit-status> <title> [step-stderr-file]}"
title="${2:-runtime step failed}"
stderr_file="${3:-}"
container="${OLA_CONTAINER:-ola-ollama-e2e}"
out="$(mktemp)"
{
  echo "exit status ${rc}"
  echo "--- ollama.log (tail)"
  if [ -f /tmp/ollama.log ]; then tail -n 5 /tmp/ollama.log | cut -c1-160; else echo "(no ollama.log)"; fi
  echo "--- OLA container log (tail)"
  docker logs --tail 25 "$container" 2>&1 | cut -c1-160
  if [ -n "$stderr_file" ] && [ -f "$stderr_file" ]; then
    echo "--- step stderr (tail)"
    tail -n 8 "$stderr_file" | cut -c1-200
  fi
} > "$out" 2>&1
# one annotation carries about 3.5 kB: keep the END (the exception), the oldest context goes first
tail -c 3300 "$out" > "$out.tail"
bash "$(dirname "$0")/ci_annotate_failure.sh" "$out.tail" "$title"
rm -f "$out" "$out.tail"
exit 0
