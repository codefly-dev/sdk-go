#!/usr/bin/env bash
# The Work Context has exactly one implementation and it is not in this
# repository: it is codefly-dev/core/workcontext. This sweeps the WHOLE
# repository — both modules, every tracked Go file — for a second one.
#
# It is a required pull-request check and it is green. There is no compatibility
# period here and no countdown: a second implementation on a ref this repository
# builds is a failure to fix, not a state to document.
#
# It is not the same check as TestNoSecondWorkContextImplementation, which walks
# from the workcontext module root and therefore cannot see the rest of the
# repository. The implementation this repository deleted lived at the ROOT, in
# package codefly, which is exactly the place that test's walk does not reach.
# Hence a sweep over every tracked file rather than over one module.
#
# The predicate is narrow on purpose: a non-test Go file that imports a signing
# primitive AND mentions the Work Context. Importing ed25519 for something else
# is not this; mentioning the capability without signing it is not this either.
# Both together is a mint or a verify, wherever in the tree it lives.
#
# Usage:
#   scripts/check-one-implementation.sh            # the working tree (what CI runs)
#   scripts/check-one-implementation.sh <ref>...   # named refs, for an operator
#
# The second form exists for whoever is retiring a ref that still carries the
# deleted implementation. Which refs those are, and when they are deleted, is
# the cold-cutover runbook's business and it lives outside this repository: this
# repository holds the rule, not a consumer inventory.
set -euo pipefail

primitives='crypto/ed25519|crypto/ecdsa'
subject='WorkContext'
status=0

carrying_in_tree() {
  local found=""
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) ;;
      *) continue ;;
    esac
    if grep -Eq "\"($primitives)\"" "$path" && grep -q "$subject" "$path"; then
      found="$found $path"
    fi
  done <<< "$(git ls-files -- '*.go')"
  printf '%s' "$found"
}

carrying_in_ref() {
  local ref="$1" found=""
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) ;;
      *) continue ;;
    esac
    local blob
    blob=$(git cat-file blob "$ref:$path" 2>/dev/null) || continue
    if printf '%s' "$blob" | grep -Eq "\"($primitives)\"" &&
       printf '%s' "$blob" | grep -q "$subject"; then
      found="$found $path"
    fi
  done <<< "$(git ls-tree -r --name-only "$ref")"
  printf '%s' "$found"
}

report() {
  local what="$1" carrying="$2"
  if [ -n "$carrying" ]; then
    status=1
    echo "FAIL $what carries a Work Context implementation:"
    for path in $carrying; do echo "       $path"; done
  else
    echo "ok   $what"
  fi
}

if [ "$#" -eq 0 ]; then
  files=$(git ls-files -- '*.go' | wc -l | tr -d ' ')
  if [ "$files" -eq 0 ]; then
    echo "no Go files tracked here: the sweep would pass for an empty repository" >&2
    exit 1
  fi
  report "working tree ($files Go files)" "$(carrying_in_tree)"
else
  for ref in "$@"; do
    git rev-parse --verify --quiet "$ref" >/dev/null || {
      echo "no such ref: $ref" >&2
      exit 1
    }
    report "$ref" "$(carrying_in_ref "$ref")"
  done
fi

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'

A wire contract has exactly one implementation, in the repository that owns the
type: codefly-dev/core/workcontext. The files above sign or verify a Work
Context here instead.

Delete them and reach core's Verifier through workcontext/core.go. This
repository once held a second implementation signing hand-written JSON. The
signatures were sound; the key id is a field inside the payload, so reading a
protobuf payload as JSON yielded no key id and the failure surfaced as "unknown
key" / "signature does not verify under key X" — which reads like a rotated key,
so keys are what everyone investigated.
MSG
fi
exit "$status"
