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
# is circular — the default branch carries the implementation until this change
# deletes it.
#
# THE BASE IS THE DEFAULT BRANCH, NOT THE REF BEING BUILT. It used to fall
# through to GITHUB_REF_NAME, and that made the same required check answer
# differently depending on which EVENT ran it:
#
#   pull_request  GITHUB_BASE_REF=main        -> main excluded, check green
#   push          GITHUB_BASE_REF is empty    -> base became the pushed branch,
#                                                main swept, check RED
#
# Measured: run 37208615216, a push build, `FAIL origin/main carries a Work
# Context implementation` listing the very files this PR deletes. Both builds
# report under one check name, so the result depended on which event landed
# last — a check whose answer depends on its trigger is worse than a check that
# is wrong, because it is right half the time.
#
# The workflow passes SWEEP_BASE explicitly from the repository's own default
# branch, so this fallback is a safety net rather than the mechanism.
base="${SWEEP_BASE:-${GITHUB_BASE_REF:-main}}"
head_ref="${SWEEP_HEAD:-${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-}}}"

# Every remote-tracking ref, by PREFIX so namespaced refs are not dropped.
# Read into a file first: a process substitution's exit status is not the shell's,
# so `done < <(git for-each-ref ...)` reports success for a git that failed.
listing=""
local_refs="$(mktemp)"
trap 'rm -f "$local_refs" ${listing:+"$listing" "$listing.err"}' EXIT
if ! git for-each-ref --format='%(refname:short)' refs/remotes/origin > "$local_refs"; then
  echo "FAIL cannot list the remote-tracking refs in this checkout." >&2
  exit 1
fi
listed=()
while IFS= read -r ref; do
  [ -n "$ref" ] || continue
  case "$ref" in
    origin | origin/HEAD) continue ;;
  esac
  listed+=("$ref")
done < "$local_refs"

# THE DENOMINATOR, from the remote itself rather than from what happens to be
# fetched locally. A stale or shallow fetch is the case a subset-sweep hides in.
#
# ASKING AND FAILING IS NOT ASKING AND GETTING NOTHING. The previous revision
# ran this with `2>/dev/null` and then guarded the comparison with
# `[ ${#published[@]} -gt 0 ]`, so an ls-remote that FAILED — no network, no
# credential, a renamed remote — produced an empty denominator and skipped the
# only check that makes the sweep's green mean anything. Measured: with the
# remote unreachable and one ref fetched locally it printed "the remote
# publishes 0 ref(s); sweeping 0 of them", "this repository publishes no ref
# other than main", and exited 0 — the same false green the glob produced,
# re-entering through the guard added to stop it. So the exit status is read,
# and the stderr is shown rather than swallowed.
listing="$(mktemp)"
if ! git ls-remote --heads origin > "$listing" 2>"$listing.err"; then
  echo "FAIL cannot list the refs this repository publishes, so there is nothing to" >&2
  echo "     hold the sweep to. git ls-remote --heads origin said:" >&2
  sed 's/^/       /' "$listing.err" >&2
  echo "     A sweep with no denominator cannot know what it did not look at, and" >&2
  echo "     reporting success from one is the defect this assertion exists for." >&2
  rm -f "$listing.err"
  exit 1
fi
rm -f "$listing.err"
published=()
while IFS= read -r name; do
  [ -n "$name" ] && published+=("$name")
done < <(sed 's|.*refs/heads/||' "$listing")

# AND THE COMPARISON IS BETWEEN SETS, NOT COUNTS. Counts agreeing is not the
# same ref list agreeing: measured, a remote that deleted one branch and
# published another left the local view holding a stale ref and missing the new
# one — two refs each side, assertion green, and the branch that actually
# carried the implementation was never opened. The sweep reported
# "ok origin/carries/the/implementation" and exited 0.
if [ ${#published[@]} -eq 0 ]; then
  echo "FAIL the remote publishes no heads at all, which no repository this gate runs in does." >&2
  echo "     That is an answer about the wrong remote, not an empty repository." >&2
  exit 1
fi

# Only one direction is asserted: every PUBLISHED ref must be visible here. A
# local ref the remote has since deleted is left in, because it is then SWEPT —
# which can produce a false failure and never a false pass, and that is the side
# to err on. The previous `-ne` compared cardinalities, which is the one
# comparison that fails in both directions at once.
missing=()
for name in "${published[@]}"; do
  found=""
  for ref in "${listed[@]}"; do
    [ "$ref" = "origin/$name" ] && found=1 && break
  done
  [ -n "$found" ] || missing+=("$name")
done
if [ ${#missing[@]} -gt 0 ]; then
  echo "FAIL the remote publishes ${#missing[@]} ref(s) this sweep cannot see: ${missing[*]}" >&2
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
