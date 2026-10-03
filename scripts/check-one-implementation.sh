#!/usr/bin/env bash
# The Work Context has exactly one implementation and it is not in this
# repository: it is codefly-dev/core/workcontext. This sweeps the WHOLE
# repository — both modules, every tracked Go file — for a second one.
#
# It runs as a job in go.yml, whose triggers are `branches: [ '**' ]` — every
# ref this repository publishes, with no naming convention in it, because a
# consumer pins a COMMIT and go.mod records a pseudo-version with no idea what
# the branch was called. The triggers said `compat/**` for three revisions
# after the comment above them stopped saying it. It is required on main by an active ruleset, under the check name
# "no second Work Context implementation". There is no compatibility period: a
# second implementation on a ref this repository builds is a failure to fix, and
# a release line that cannot meet the rule is retired by the owner rather than
# exempted.
#
# It is not the same check as the Go gates, and it is no longer the only gate
# that reads the root module: TestEveryImportIsOnItsModulesAllowlist and
# TestNoCodecTouchesACapabilityByType type-check BOTH modules with
# x/tools/go/packages. This script is what runs over every PUBLISHED REF, where
# there is no checkout to type-check — which is why it reads imports with
# go/parser (scripts/importsof) rather than with a regex.
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

# Where this script lives, so the import reader beside it can be built.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Any of these in an import path is a signature, a MAC, or a library that mints
# bearer tokens. The bare "crypto" package is included: crypto.Signer signs
# Ed25519 with no ed25519 import anywhere.
# Signatures, MACs and anything that mints a bearer token. The bare "crypto" is
# included: crypto.Signer signs Ed25519 with no ed25519 import anywhere.
# crypto/cipher and the block ciphers are here because a GMAC or a CMAC is a
# MAC assembled from a cipher, which names no MAC.
primitives='^crypto$|^crypto/hkdf$|^crypto/pbkdf2$|^crypto/sha512$|^crypto/sha1$|^crypto/sha3$|^crypto/md5$|^crypto/ed25519$|^crypto/ecdsa$|^crypto/rsa$|^crypto/dsa$|^crypto/hmac$|^crypto/ecdh$|^crypto/elliptic$|^crypto/subtle$|^crypto/cipher$|^crypto/aes$|^crypto/des$|^crypto/rc4$|^crypto/sha3$|x/crypto/|jose|jwt|jwx|paseto|macaroon|branca|ed25519'
# Second encodings of the message. protojson is a complete JSON encoding of a
# protobuf message on its own, which is how the deleted implementation's payload
# would come back without an encoding/json import.
# The LOW-LEVEL protobuf runtime and the LEGACY protobuf module belong here as
# well, and did not until the two gates were compared entry by entry: the AST
# gate banned protoiface, protoimpl and github.com/golang/protobuf/proto while
# this script passed all three — measured, `ok working tree (4 Go files)`,
# exit 0 — in the module where this script is the only gate. A message's own
# ProtoMethods().Unmarshal is a complete decode naming no codec package, and the
# legacy module's proto.Unmarshal is the same capability at another path.
encoders='encoding/protojson|encoding/protowire|known/anypb|^encoding/gob$|^encoding/asn1$|^encoding/xml$|runtime/protoiface|runtime/protoimpl|^github.com/golang/protobuf/proto$'
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
    # The two digests, and the receipts store's row digest. A hash is not a
    # signature; a hand-rolled HMAC over one is the residue named in the header.
    'workcontext/cache_partition.go|crypto/sha256') return 0 ;;
    'receipts/digest.go|crypto/sha256') return 0 ;;
    'receipts/postgres.go|crypto/sha256') return 0 ;;
    # The receipts DIGEST, which canonicalises a receipt REQUEST. By exact
    # path: this was `receipts/*`, permitting encoding/json anywhere under
    # receipts, while the AST gate named one file — so the two gates disagreed
    # about the same directory and the looser one was this script, which is the
    # only gate the ref sweep runs. Measured from the tree: receipts/digest.go
    # is the only non-test file there that imports it.
    'receipts/digest.go|encoding/json') return 0 ;;
  esac
  return 1
}

# IMPORTS ARE READ BY GO'S OWN PARSER, not by a regex over lines.
#
# The awk extractor this replaces was rewritten three times for exactly this
# class, and each rewrite was walked past by source that compiles: a ")" inside
# a comment closing the import block, a raw-string path before a quoted one on
# the same line, the keyword followed by a newline, a comment spanning lines,
# and
#
#     import "\x63rypto/ed25519"
#
# which IS crypto/ed25519 to the compiler and is not that string to anything
# matching text. The escape cannot be closed by any amount of regex, and the
# language's own parser closes all five at once — the question was always "what
# does Go think this file imports".
#
# It matters most HERE. The AST gate reads the working tree; this script is what
# the ref sweep runs over every published ref, ALONE, so each shape above was a
# complete bypass of the required check for any branch a consumer can pin.
# IMPORTSOF_BIN names a prebuilt reader. The script builds one otherwise; the
# variable exists because the sweep's own tests run it in throwaway
# repositories, and building the reader once for all of them is the difference
# between a second and a minute.
helper="${IMPORTSOF_BIN:-}"
build_helper() {
  [ -n "$helper" ] && return 0
  helper="$(mktemp -d)/importsof"
  if ! go build -o "$helper" "$here/importsof"; then
    echo "FAIL cannot build the import reader at $here/importsof." >&2
    echo "     Imports are read with go/parser now, because a regex over lines cannot" >&2
    echo "     read Go: an escaped path is one string to the compiler and another to grep." >&2
    exit 1
  fi
}

# imports_of_files <listfile> -> "path<TAB>importpath" per import.
#
# A file that does not parse is a FAILURE and never a file with no imports.
imports_of_files() {
  build_helper
  if ! "$helper" < "$1"; then
    echo "FAIL cannot read the imports of the files listed above." >&2
    echo "     A file this sweep cannot parse is not a file it has cleared." >&2
    exit 1
  fi
}

# offending_import <path> <importpath> -> true when this import is a finding.
offending_import() {
  local path="$1" imported="$2"
  case "$imported" in
    'crypto/tls'|'crypto/x509')
      # TLS plumbing, still held to the allowlist.
      allowed "$path" "$imported" && return 1
      return 0
      ;;
    'crypto/rand')
      # Randomness is not a key.
      return 1
      ;;
    'crypto/sha256')
      # The ONE hash with uses here — three digests — held to them by the AST
      # gate's file and symbol rule. The others are not waved through:
      # hkdf.Extract(sha512.New, …) and pbkdf2.Key(sha512.New, …) are HMAC, and
      # both passed this script while `crypto/sha512` sat in the "a hash is not
      # a signature" list beside it.
      allowed "$path" "$imported" && return 1
      return 0
      ;;
  esac
  if printf '%s' "$imported" | grep -Eq "($primitives)|($encoders)|($envelope)" ||
    [ "$imported" = "encoding/json" ]; then
    allowed "$path" "$imported" && return 1
    return 0
  fi
  return 1
}

carrying_in_tree() {
  local found="" tracked list imports path imported
  if ! tracked=$(git ls-files -- '*.go'); then
    echo "FAIL cannot enumerate the tracked Go files in this checkout." >&2
    exit 1
  fi
  list=$(mktemp); imports=$(mktemp)
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) printf '%s\n' "$path" >> "$list" ;;
    esac
  done <<< "$tracked"
  imports_of_files "$list" > "$imports"
  while IFS=$'\t' read -r path imported; do
    [ -n "$imported" ] || continue
    if offending_import "$path" "$imported"; then
      found="$found$path imports $imported"$'\n'
    fi
  done < "$imports"
  rm -f "$list" "$imports"
  printf '%s' "$found"
}

carrying_in_ref() {
  local ref="$1" found="" entries list imports work path imported index=0
  if ! entries=$(git ls-tree -r --name-only "$ref"); then
    echo "FAIL cannot enumerate $ref, so it has not been swept." >&2
    exit 1
  fi
  work=$(mktemp -d); list=$(mktemp); imports=$(mktemp)
  # Each blob's path in the REF is recorded beside its temporary copy, so a
  # finding names that path and not something under /tmp.
  local -a origin=()
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) ;;
      *) continue ;;
    esac
    # THE SAME FAIL-OPEN AS THE TREE'S, and this one needed no error at all:
    # `git ls-tree -r` names gitlinks as well as blobs, so a submodule whose
    # path ends in `.go` is listed and `git cat-file blob` cannot read it.
    # Measured: `fatal: bad file` swallowed by 2>/dev/null, the source emptied,
    # and the ref reported `ok` with exit 0.
    if ! git cat-file blob "$ref:$path" > "$work/$index.go" 2>"$work/err"; then
      echo "FAIL cannot read $ref:$path, so this ref has not been swept. git said:" >&2
      sed 's/^/       /' "$work/err" >&2
      exit 1
    fi
    origin[index]="$path"
    printf '%s\n' "$work/$index.go" >> "$list"
    index=$((index + 1))
  done <<< "$entries"
  if [ "$index" -gt 0 ]; then
    imports_of_files "$list" > "$imports"
    while IFS=$'\t' read -r path imported; do
      [ -n "$imported" ] || continue
      local base="${path##*/}"
      path="${origin[${base%.go}]}"
      if offending_import "$path" "$imported"; then
        found="$found$path imports $imported"$'\n'
      fi
    done < "$imports"
  fi
  rm -rf "$work"; rm -f "$list" "$imports"
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
  # THE SUBSTITUTION'S EXIT STATUS IS READ. `report … "$(carrying_in_tree)"` threw
  # it away: a fatal `exit 1` inside the function ran in the command
  # substitution's SUBSHELL, so the script carried on, report saw no findings,
  # and the ref was announced `ok` with exit 0 — measured, with the FAIL text
  # printed directly above the `ok`. A fix that reports its own failure and then
  # passes is the defect it was fixing.
  if ! carrying=$(carrying_in_tree); then
    exit 1
  fi
  report "working tree ($files Go files)" "$carrying"
else
  for ref in "$@"; do
    git rev-parse --verify --quiet "$ref" >/dev/null || {
      echo "no such ref: $ref" >&2
      exit 1
    }
    if ! carrying=$(carrying_in_ref "$ref"); then
      exit 1
    fi
    report "$ref" "$carrying"
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
