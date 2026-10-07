#!/usr/bin/env bash
# Publishes the tail of a test log as a GitHub error annotation. Job logs and artifacts are not always readable
# from outside the runner, annotations are (REST: check-runs/<id>/annotations), so a red live job says WHY.
# Usage: ci_annotate_failure.sh <log-file> [title]
set -u
file="${1:?usage: ci_annotate_failure.sh <log-file> [title]}"
title="${2:-test failed}"
# keep the END of the log (the assertion and the summary line), not its beginning, when the lines are long
msg=$(tail -n 45 "$file" 2>/dev/null | cut -c1-400 | tail -c 3500)
msg=${msg//'%'/'%25'}
msg=${msg//$'\r'/'%0D'}
msg=${msg//$'\n'/'%0A'}
echo "::error title=${title}::${msg}"
