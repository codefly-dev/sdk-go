#!/usr/bin/env bash
# Sweep EVERY ref this repository publishes for a second Work Context
# implementation, except the one the current change is becoming.
#
# This exists as a script rather than inline in go.yml for one reason: the
# inline version was wrong for weeks and nothing could test it. It listed refs
# with
#
#     git for-each-ref 'refs/remotes/origin/*'
#
# and `*` DOES NOT CROSS A SLASH, so every branch with a slash in its name was
# silently dropped — compat/*, feat/*, dependabot/*, anything namespaced. The
# CI log said "sweeping 1 other published ref(s)" and "ok origin/badges" and
# the check went green while origin/dependabot/go_modules/gomod-06d3dc2861
# published workcontext/work_context.go importing crypto/ed25519.
#
# Two changes follow from that, and the second matters more than the first:
#
#   1. Refs are listed BY PREFIX (refs/remotes/origin), which git matches
#      without globbing, so a namespaced ref is included.
#   2. SWEPT IS ASSERTED AGAINST LISTED. A gate that sweeps a subset and
#      reports success is worse than no gate, because the green is evidence.
#      The remote's own branch list is the denominator, and a mismatch fails
#      rather than passing quietly.
#
# Usage:
#   scripts/sweep-published-refs.sh                # base/head from the environment
#   SWEEP_BASE=main SWEEP_HEAD=my-branch scripts/sweep-published-refs.sh
#   SWEEP_LIST_ONLY=1 scripts/sweep-published-refs.sh   # print the refs, sweep nothing
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The ref this change is becoming, and the ref it merges into, are both
# excluded: the working-tree sweep covers the former, and sweeping the latter
# is circular — main carries the implementation until this change deletes it.
base="${SWEEP_BASE:-${GITHUB_BASE_REF:-${GITHUB_REF_NAME:-main}}}"
head_ref="${SWEEP_HEAD:-${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-}}}"

# Every remote-tracking ref, by PREFIX so namespaced refs are not dropped.
listed=()
while IFS= read -r ref; do
  [ -n "$ref" ] || continue
  case "$ref" in
    origin | origin/HEAD) continue ;;
  esac
  listed+=("$ref")
done < <(git for-each-ref --format='%(refname:short)' refs/remotes/origin)

# THE DENOMINATOR, from the remote itself rather than from what happens to be
# fetched locally. A stale or shallow fetch is the case a subset-sweep hides in.
published=()
while IFS= read -r name; do
  [ -n "$name" ] && published+=("$name")
done < <(git ls-remote --heads origin 2>/dev/null | sed 's|.*refs/heads/||')

if [ ${#published[@]} -gt 0 ] && [ ${#listed[@]} -ne ${#published[@]} ]; then
  echo "FAIL the sweep can see ${#listed[@]} ref(s) and the remote publishes ${#published[@]}." >&2
  echo "     Listed:    ${listed[*]}" >&2
  echo "     Published: ${published[*]}" >&2
  echo "     A sweep over a subset that reports success is worse than no sweep." >&2
  echo "     Fetch every head first: git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*'" >&2
  exit 1
fi

refs=()
for ref in "${listed[@]}"; do
  [ "$ref" = "origin/$base" ] && continue
  if [ -n "$head_ref" ] && [ "$ref" = "origin/$head_ref" ]; then
    continue
  fi
  refs+=("$ref")
done

if [ -n "${SWEEP_LIST_ONLY:-}" ]; then
  printf '%s\n' "${refs[@]}"
  exit 0
fi

echo "the remote publishes ${#published[@]} ref(s); sweeping ${#refs[@]} of them"
echo "(the working tree is swept separately, and $base is swept by its own push build)"
if [ ${#refs[@]} -eq 0 ]; then
  echo "this repository publishes no ref other than $base and ${head_ref:-this one}"
  exit 0
fi
"$here/check-one-implementation.sh" "${refs[@]}"
