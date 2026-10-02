#!/usr/bin/env bash
# The Work Context has exactly one implementation and it is not in this
# repository: it is codefly-dev/core/workcontext. This sweeps the WHOLE
# repository — both modules, every tracked Go file — for a second one.
#
# It runs as a job in go.yml, which is the workflow that builds every ref this
# repository publishes (main and compat/**), so the gate holds wherever the
# build holds. It is required on main by an active ruleset, under the check name
# "no second Work Context implementation". There is no compatibility period: a
# second implementation on a ref this repository builds is a failure to fix, and
# a release line that cannot meet the rule is retired by the owner rather than
# exempted.
#
# It is not the same check as TestNoSecondWorkContextImplementation, which walks
# from the workcontext module root and therefore cannot see the rest of the
# repository. The implementation this repository deleted lived at the ROOT, in
# package codefly, which is exactly the place that test's walk does not reach.
#
# THE PREDICATE IS AN ABSOLUTE BAN ON SIGNING, with a named allowlist — not a
# conjunction. It used to be "imports a signing primitive AND mentions
# WorkContext", which a second implementation defeats by putting the signer in
# one file and the wrapper in another; and its pattern was anchored on the
# opening quote, so "golang.org/x/crypto/ed25519" did not match at all. Now any
# import of a signature, a MAC or a JOSE/JWT library is a finding wherever it
# is, and the exceptions are listed by path with a reason. crypto/sha256 is
# deliberately not banned: a hash is not a signature, and two digests here need
# one.
#
# Usage:
#   scripts/check-one-implementation.sh            # the working tree (what CI runs)
#   scripts/check-one-implementation.sh <ref>...   # named refs, for an operator
#
# The second form is for whoever retires a ref that still carries the deleted
# implementation. Which refs those are is the cold-cutover runbook's business and
# it lives outside this repository: this repository holds the rule, not a
# consumer inventory.
set -euo pipefail

# Any of these in an import path is a signature, a MAC, or a library that mints
# bearer tokens. The bare "crypto" package is included: crypto.Signer signs
# Ed25519 with no ed25519 import anywhere.
primitives='"crypto"|crypto/ed25519|crypto/ecdsa|crypto/rsa|crypto/dsa|crypto/hmac|crypto/ecdh|crypto/elliptic|crypto/subtle|x/crypto/|jose|jwt|jwx|paseto|macaroon|branca'
# Second encodings of the message. protojson is a complete JSON encoding of a
# protobuf message on its own, which is how the deleted implementation's payload
# would come back without an encoding/json import.
encoders='encoding/protojson|encoding/gob|encoding/asn1|encoding/xml'
status=0

# allowed <path> <pattern> — the exceptions, each with a reason in the comment.
# The mint client builds and owns its own TLS transport, which needs tls for the
# configuration and x509 for the caller's root pool. Nothing else here may.
allowed() {
  case "$1|$2" in
    'workcontext/mint.go|'*'crypto/tls'*) return 0 ;;
    'workcontext/mint.go|'*'crypto/x509'*) return 0 ;;
    'tls.go|'*'crypto/tls'*) return 0 ;;
    'tls.go|'*'crypto/x509'*) return 0 ;;
    # The receipts digest canonicalises a receipt REQUEST, never a capability.
    'receipts/digest.go|'*'encoding/protojson'*) return 0 ;;
  esac
  return 1
}

# findings <path> <contents-on-stdin-file> -> prints each offending import
offending_imports() {
  local path="$1" file="$2" line
  while IFS= read -r line; do
    case "$line" in
      *'crypto/tls'*|*'crypto/x509'*|*'crypto/sha256'*|*'crypto/md5'*|*'crypto/sha1'*|*'crypto/sha512'*|*'crypto/rand'*)
        # Hashes, randomness and TLS plumbing are not signatures. tls/x509 are
        # still held to the allowlist below.
        case "$line" in
          *'crypto/tls'*|*'crypto/x509'*)
            allowed "$path" "$line" || printf '%s\n' "$line"
            ;;
        esac
        continue
        ;;
    esac
    if printf '%s' "$line" | grep -Eq "($primitives)"; then
      allowed "$path" "$line" || printf '%s\n' "$line"
      continue
    fi
    if printf '%s' "$line" | grep -Eq "($encoders)"; then
      allowed "$path" "$line" || printf '%s\n' "$line"
    fi
  done < "$file"
}

carrying_in_tree() {
  local found="" tmp
  tmp=$(mktemp)
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) ;;
      *) continue ;;
    esac
    grep -E '^\s*(import\s+)?(_\s+|[A-Za-z0-9_]+\s+)?"' "$path" > "$tmp" 2>/dev/null || : > "$tmp"
    local bad
    bad=$(offending_imports "$path" "$tmp")
    if [ -n "$bad" ]; then
      found="$found $path"
    fi
  done <<< "$(git ls-files -- '*.go')"
  rm -f "$tmp"
  printf '%s' "$found"
}

carrying_in_ref() {
  local ref="$1" found="" tmp
  tmp=$(mktemp)
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) ;;
      *) continue ;;
    esac
    git cat-file blob "$ref:$path" 2>/dev/null |
      grep -E '^\s*(import\s+)?(_\s+|[A-Za-z0-9_]+\s+)?"' > "$tmp" 2>/dev/null || : > "$tmp"
    local bad
    bad=$(offending_imports "$path" "$tmp")
    if [ -n "$bad" ]; then
      found="$found $path"
    fi
  done <<< "$(git ls-tree -r --name-only "$ref")"
  rm -f "$tmp"
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
type: codefly-dev/core/workcontext. The files above import a signature, a MAC, a
token library or a second encoding of the message.

There is no "and it also mentions WorkContext" condition any more: that was
satisfied by splitting a signer across two files. If a file above has an honest
need for one of these, add it to allowed() by path WITH A REASON, so the next
reader sees the argument rather than the exception.

Delete them and reach core's Verifier through workcontext/core.go. This
repository once held a second implementation signing hand-written JSON. The
signatures were sound; the key id is a field inside the payload, so reading a
protobuf payload as JSON yielded no key id and the failure surfaced as "unknown
key" / "signature does not verify under key X" — which reads like a rotated key,
so keys are what everyone investigated.
MSG
fi
exit "$status"
