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
# THE PREDICATE IS DENY BY DEFAULT: an import not on its module's list in
# scripts/allowed-imports.txt is a finding. It used to be a ban on signing with
# a named allowlist — a denylist — and it is not that any more. It used to be "imports a signing primitive AND mentions
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

# THE POLICY IS DENY BY DEFAULT and it is read from scripts/allowed-imports.txt,
# which the Go gate reads too.
#
# What was here was three regexes and a per-file exception list — a DENYLIST,
# and every round of review found the next name it was missing. The last pair
# was `crypto/mldsa` signing a `WorkContextV1` that `encoding/json/v2` had
# encoded in the deleted format; a reviewer ran this script's extracted
# predicate over both and both were "permitted", along with protodelim,
# grpc/encoding and `C`. The allowlist existed by then — in `go test`, which
# reads a checkout, while THIS is the only thing that runs over a published ref
# and is the required check. One policy, both places.
status=0

policy="$here/allowed-imports.txt"
if [ ! -r "$policy" ]; then
  echo "FAIL cannot read the import policy at $policy." >&2
  echo "     Deny-by-default with no list permits nothing or everything; neither is a gate." >&2
  exit 1
fi

# allowed_root and allowed_leaf hold one permitted import per line as
# `<path>` or `<path> file file …`, bracketed so a fixed-string match cannot
# match a prefix: `crypto/sha` must not pass because `crypto/sha256` is listed.
allowed_root="$(mktemp)"
allowed_leaf="$(mktemp)"
awk '$1 == "root" { $1 = ""; sub(/^ /, ""); print "<" $0 ">" }' "$policy" > "$allowed_root"
awk '$1 == "leaf" { $1 = ""; sub(/^ /, ""); print "<" $0 ">" }' "$policy" > "$allowed_leaf"
# Historical paths, added ONLY in ref mode. See the policy file's own comment:
# deny-by-default describes today's tree, and sweeping two years of tags with it
# flagged 33 clean versions for a renamed core package and a Postgres driver.
if [ "$#" -gt 0 ]; then
  awk '$1 == "legacy" { print "<" $2 ">" }' "$policy" >> "$allowed_root"
  awk '$1 == "legacy" { print "<" $2 ">" }' "$policy" >> "$allowed_leaf"
fi
# module_of <path> -> root | leaf
module_of() {
  case "$1" in
    workcontext/*) printf 'leaf\n' ;;
    *) printf 'root\n' ;;
  esac
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
#
# `import "C"` is not an import path at all, it is an exit from every rule here:
# a MAC built through the host's crypto library names no Go package. It is
# named so the message says that, rather than only "not on the list".
offending_import() {
  local path="$1" imported="$2" list entry files
  if [ "$imported" = "C" ]; then
    return 0
  fi
  case "$(module_of "$path")" in
    leaf) list="$allowed_leaf" ;;
    *) list="$allowed_root" ;;
  esac
  # Module-wide: the line is just the path.
  grep -qxF "<$imported>" "$list" && return 1
  # Or held to NAMED FILES, which is what keeps this as strict as the denylist
  # it replaced: that one held encoding/json to named paths, and a module-wide
  # line let any root file have it.
  entry=$(grep -F "<$imported " "$list" | head -1)
  if [ -n "$entry" ]; then
    files=${entry#"<$imported "}
    files=${files%>}
    for allowed_file in $files; do
      [ "$allowed_file" = "$path" ] && return 1
    done
  fi
  return 0
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
type: codefly-dev/core/workcontext. The imports above are not on their module's
allowlist in scripts/allowed-imports.txt.

THIS IS DENY BY DEFAULT, and that is the point. The rule here was a denylist of
names for ten rounds of review and every round found the next name — hkdf, then
sha512, then protoiface, and finally crypto/mldsa signing a WorkContextV1 that
encoding/json/v2 had encoded in the deleted format, with every gate green. If an
import above is honest, add it to scripts/allowed-imports.txt WITH A REASON, in
a reviewed diff. That is the cost, and it is one line instead of a round.

`import "C"` is refused outright: cgo is not a package name to add to a list, it
is an exit from every rule here — a MAC built through the host's crypto library
names no Go package at all.

Reach core's Verifier through workcontext/core.go. This repository once held a
second implementation signing hand-written JSON. The signatures were sound; the
key id is a field inside the payload, so reading a protobuf payload as JSON
yielded no key id and the failure surfaced as "unknown key" / "signature does
not verify under key X" — which reads like a rotated key, so keys are what
everyone investigated.
MSG
fi
exit "$status"
