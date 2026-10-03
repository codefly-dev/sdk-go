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
# is, and the exceptions are listed by path with a reason.
#
# WHAT IT MATCHES IS THE IMPORT PATH, extracted from the import block. It used
# to match a LINE against a regex that tried to recognise an import's shape —
# `([._]\s+|[A-Za-z0-9_]+\s+)?"` — which a non-ASCII alias (`ψ
# "crypto/ed25519"`) and a comment-prefixed line (`/* x */ "crypto/ed25519"`)
# both walked straight past. Nothing here tries to recognise an alias any more:
# the path inside the quotes is what is tested, whatever precedes it.
#
# WHAT IT DOES NOT CATCH, stated because the claim was broader than the check:
# a hand-written HMAC over crypto/sha256, or a GMAC built from crypto/cipher,
# constructs a MAC out of parts that are not themselves MACs. crypto/cipher and
# the block ciphers are banned below, which leaves the hash. crypto/sha256
# cannot be banned — two digests here need it — so in the leaf module the AST
# gate holds it to ONE FILE and a few symbols, and in the root module this
# residue is real and is closed by review, not by this script. "Any MAC is a
# finding" was a list of names; this is what the list reaches.
#
# proto.Unmarshal is likewise not banned anywhere: this is an SDK over core's
# protobuf API and the root module decodes core's messages constantly. What
# makes a second PARSER need more than that is opening the envelope, which is
# base64 — so the decoders below are banned repository-wide, and in the leaf
# module the AST gate additionally holds proto.Unmarshal to named types.
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
# Signatures, MACs and anything that mints a bearer token. The bare "crypto" is
# included: crypto.Signer signs Ed25519 with no ed25519 import anywhere.
# crypto/cipher and the block ciphers are here because a GMAC or a CMAC is a
# MAC assembled from a cipher, which names no MAC.
primitives='^crypto$|^crypto/ed25519$|^crypto/ecdsa$|^crypto/rsa$|^crypto/dsa$|^crypto/hmac$|^crypto/ecdh$|^crypto/elliptic$|^crypto/subtle$|^crypto/cipher$|^crypto/aes$|^crypto/des$|^crypto/rc4$|^crypto/sha3$|x/crypto/|jose|jwt|jwx|paseto|macaroon|branca'
# Second encodings of the message. protojson is a complete JSON encoding of a
# protobuf message on its own, which is how the deleted implementation's payload
# would come back without an encoding/json import.
encoders='encoding/protojson|encoding/protowire|known/anypb|^encoding/gob$|^encoding/asn1$|^encoding/xml$'
# Opening a credential's envelope by hand. base64 plus proto.Unmarshal is the
# whole of a second parser, and the AST gate reaches only the workcontext module
# — a compiling root package with a base64/JSON credential decoder and its own
# seal rule passed this sweep.
#
# base64 is not the only way to spell it, which is why this is a list and not
# one path: encoding/pem decodes a base64 body, mime.WordDecoder decodes
# base64, and base32/ascii85 are alternative envelopes a host could be talked
# into. encoding/hex and encoding/binary are deliberately absent: neither can
# open core's envelope, which is base64url.
envelope='^encoding/base64$|^encoding/base32$|^encoding/ascii85$|^encoding/pem$|^mime$|^mime/'

status=0

# allowed <path> <pattern> — the exceptions, each with a reason in the comment.
# The mint client builds and owns its own TLS transport, which needs tls for the
# configuration and x509 for the caller's root pool. Nothing else here may.
allowed() {
  case "$1|$2" in
    'workcontext/mint.go|crypto/tls') return 0 ;;
    'workcontext/mint.go|crypto/x509') return 0 ;;
    'tls.go|crypto/tls') return 0 ;;
    'tls.go|crypto/x509') return 0 ;;
    # The receipts digest canonicalises a receipt REQUEST, never a capability.
    'receipts/digest.go|google.golang.org/protobuf/encoding/protojson') return 0 ;;
    # ENCODES a tenant and installation id into a cache key; opens no envelope.
    # The AST gate additionally holds that file to the ENCODE methods, which is
    # the half this script cannot check.
    'workcontext/cache_partition.go|encoding/base64') return 0 ;;
    # The runtime's own configuration document, which is not a capability. The
    # AST gate cannot reach the root module, so this is named here instead.
    'configuration_document.go|encoding/json') return 0 ;;
    # The mint endpoint's two HTTP bodies. In the workcontext module the AST
    # gate additionally holds this to the TWO TYPES; here it is by path only,
    # which is the weaker half and is why the AST gate exists.
    'workcontext/mint.go|encoding/json') return 0 ;;
    # One call: the mint response's Content-Type must be declared and must be
    # application/json. mime is banned otherwise because WordDecoder decodes
    # base64 with no base64 import.
    'workcontext/mint.go|mime') return 0 ;;
    # Effect receipts, whose rows are JSON and are not capabilities.
    'receipts/'*'|encoding/json') return 0 ;;
  esac
  return 1
}

# import_paths <file> -> every imported path, one per line.
#
# It takes what is INSIDE the quotes and never tries to recognise the alias in
# front of it. The previous version matched the whole line against a regex for
# an import's shape, which a non-ASCII alias and a `/* comment */` prefix both
# defeated — and in the root module this sweep is the only gate, so each was a
# complete bypass.
import_paths() {
  awk '
    /^[[:space:]]*import[[:space:]]*\(/ { inblock = 1; next }
    inblock && /^[[:space:]]*\)/        { inblock = 0; next }
    inblock || /^[[:space:]]*import[[:space:]]/ {
      # Double-quoted, which is every import gofmt produces.
      if (match($0, /"[^"]+"/)) { print substr($0, RSTART + 1, RLENGTH - 2); next }
      # And a RAW-STRING path. gofmt rewrites `crypto/ed25519` to the quoted
      # form, so this cannot survive a formatted tree — but the sweep reads
      # what is committed, not what gofmt would have written, and a reviewer
      # confirmed the raw-string form passed.
      if (match($0, /`[^`]+`/)) { print substr($0, RSTART + 1, RLENGTH - 2) }
    }
  ' "$1"
}

# offending_imports <path> <file> -> prints each offending import PATH
offending_imports() {
  local path="$1" file="$2" imported
  while IFS= read -r imported; do
    [ -n "$imported" ] || continue
    case "$imported" in
      'crypto/tls'|'crypto/x509')
        # TLS plumbing, still held to the allowlist.
        allowed "$path" "$imported" || printf '%s\n' "$imported"
        continue
        ;;
      'crypto/sha256'|'crypto/md5'|'crypto/sha1'|'crypto/sha512'|'crypto/rand')
        # A hash is not a signature and randomness is not a key. The residue —
        # a hand-written HMAC over an allowed hash — is named in the header.
        continue
        ;;
    esac
    if printf '%s' "$imported" | grep -Eq "($primitives)"; then
      allowed "$path" "$imported" || printf '%s\n' "$imported"
      continue
    fi
    if printf '%s' "$imported" | grep -Eq "($encoders)"; then
      allowed "$path" "$imported" || printf '%s\n' "$imported"
      continue
    fi
    if printf '%s' "$imported" | grep -Eq "($envelope)" || [ "$imported" = "encoding/json" ]; then
      allowed "$path" "$imported" || printf '%s\n' "$imported"
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
    import_paths "$path" > "$tmp" 2>/dev/null || : > "$tmp"
    local bad
    bad=$(offending_imports "$path" "$tmp")
    if [ -n "$bad" ]; then
      while IFS= read -r imported; do
        found="$found$path imports $imported"$'\n'
      done <<< "$bad"
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
    git cat-file blob "$ref:$path" > "$tmp.src" 2>/dev/null || : > "$tmp.src"
    import_paths "$tmp.src" > "$tmp" 2>/dev/null || : > "$tmp"
    local bad
    bad=$(offending_imports "$path" "$tmp")
    if [ -n "$bad" ]; then
      while IFS= read -r imported; do
        found="$found$path imports $imported"$'\n'
      done <<< "$bad"
    fi
  done <<< "$(git ls-tree -r --name-only "$ref")"
  rm -f "$tmp" "$tmp.src"
  printf '%s' "$found"
}

report() {
  local what="$1" carrying="$2"
  if [ -n "$carrying" ]; then
    status=1
    echo "FAIL $what carries a Work Context implementation:"
    # The offending IMPORT is printed beside the file. Naming only the file
    # left whoever reads the CI log to re-derive which import was the finding.
    while IFS= read -r line; do
      [ -n "$line" ] && echo "       $line"
    done <<< "$carrying"
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
