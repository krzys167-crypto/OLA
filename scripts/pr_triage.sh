#!/usr/bin/env bash
# pr_triage.sh — read-only, git-only triage of pull request heads.
#
# Needs no GitHub API access. It cannot tell whether a PR is open or closed;
# it only reports what the git graph and file contents show.
#
#   git fetch --no-tags origin '+refs/pull/*/head:refs/remotes/prs/*'
#   scripts/pr_triage.sh [BASE_REF] [STACK_PR]      # defaults: main 103
#
# Columns:
#   pr      pull request number
#   head    short SHA of the PR head
#   date    committer date of the head
#   signed  yes/no — head commit carries a signature header (any signer)
#   ahead   commits in PR not in BASE_REF
#   behind  commits in BASE_REF not in PR
#   files   files changed since the merge base
#   wf      of those, files under .github/workflows/
#   state   MERGED_ANCESTRY  head is an ancestor of BASE_REF
#           CONTENT_ON_MAIN  every file the PR touched is identical on BASE_REF (squash-merged or superseded)
#           DIVERGED         needs a human decision
#           EMPTY_DIFF       no file changes
#   on103   relation to STACK_PR: ANCESTOR, CONTENT_IN (all touched files identical there), n/m (files identical), -
#   subject first line of the head commit
set -u
BASE="${1:-main}"
STACK="${2:-103}"
cd "$(git rev-parse --show-toplevel)"
MAIN=$(git rev-parse "$BASE")
STACK_REF="refs/remotes/prs/${STACK}"
STACK_TIP=$(git rev-parse --verify -q "$STACK_REF" || true)

printf "pr\thead\tdate\tsigned\tahead\tbehind\tfiles\twf\tstate\ton103\tsubject\n"
for ref in $(git for-each-ref --format='%(refname)' refs/remotes/prs | sort -t/ -k4 -n); do
  n=${ref##*/}
  h=$(git rev-parse "$ref")
  date=$(git log -1 --format=%cs "$h")
  subj=$(git log -1 --format=%s "$h" | cut -c1-90)
  signed=no; git cat-file commit "$h" | grep -q '^gpgsig' && signed=yes
  read -r behind ahead < <(git rev-list --left-right --count "$MAIN...$h")
  files=0; wf=0; state="DIVERGED"; on103="-"
  if git merge-base --is-ancestor "$h" "$MAIN"; then
    state="MERGED_ANCESTRY"
  else
    mb=$(git merge-base "$MAIN" "$h" 2>/dev/null || true)
    if [ -z "$mb" ]; then state="NO_MERGE_BASE"; else
      mapfile -t flist < <(git diff --name-only "$mb" "$h")
      files=${#flist[@]}
      wf=$(printf "%s\n" "${flist[@]}" | grep -c '^\.github/workflows/' || true)
      if [ "$files" -eq 0 ]; then state="EMPTY_DIFF"
      elif git diff --quiet "$h" "$MAIN" -- "${flist[@]}" 2>/dev/null; then state="CONTENT_ON_MAIN"
      fi
      if [ -n "$STACK_TIP" ] && [ "$n" != "$STACK" ] && [ "$files" -gt 0 ]; then
        if git merge-base --is-ancestor "$h" "$STACK_TIP"; then on103="ANCESTOR"
        elif git diff --quiet "$h" "$STACK_TIP" -- "${flist[@]}" 2>/dev/null; then on103="CONTENT_IN"
        else
          same=0
          for f in "${flist[@]}"; do git diff --quiet "$h" "$STACK_TIP" -- "$f" 2>/dev/null && same=$((same+1)); done
          on103="${same}/${files}"
        fi
      fi
    fi
  fi
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$n" "${h:0:7}" "$date" "$signed" "$ahead" "$behind" "$files" "$wf" "$state" "$on103" "$subj"
done
