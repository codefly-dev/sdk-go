#!/usr/bin/env bash
# Every branch CI builds is checked for a second Work Context implementation,
# not only the one being pushed.
#
# TestNoSecondWorkContextImplementation guards the tree it runs in, and that is
# the right place for it — but a branch's CI run uses that branch's own tree and
# workflow, so a test added on main can never execute on compat/v0.1.65. The
# branches that still carry the deleted JSON implementation would therefore stay
# green while containing exactly what the rule forbids. This sweep closes that:
# it reads every ref CI builds straight out of the object database and reports
# the ones carrying an implementation.
#
# It is deliberately NOT part of the pull-request checks. The refs it names are
# retired by the owner at the cold cutover, so until then it is red by design —
# a visible countdown rather than a silence. See docs/cutover.md.
#
# The predicate is narrow on purpose: a non-test Go file that imports a signing
# primitive AND mentions the Work Context. Importing ed25519 for something else
# is not this; mentioning the capability without signing it is not this either.
# Both together is a mint or a verify, wherever in the tree it lives — which
# matters because on the release lines these files sit at the repository root
# rather than under workcontext/.
set -euo pipefail

primitives='crypto/ed25519|crypto/ecdsa'
subject='WorkContext'
status=0

refs=$(git for-each-ref --format='%(refname:short)' \
  'refs/remotes/origin/main' 'refs/remotes/origin/compat/*' 'refs/remotes/origin/feat/*compat*')

if [ -z "$refs" ]; then
  echo "no refs to sweep: fetch the remote branches first (git fetch origin '+refs/heads/*:refs/remotes/origin/*')" >&2
  exit 1
fi

for ref in $refs; do
  carrying=""
  while IFS= read -r path; do
    case "$path" in
      *_test.go) continue ;;
      *.go) ;;
      *) continue ;;
    esac
    blob=$(git cat-file blob "$ref:$path" 2>/dev/null) || continue
    if printf '%s' "$blob" | grep -Eq "\"($primitives)\"" &&
       printf '%s' "$blob" | grep -q "$subject"; then
      carrying="$carrying $path"
    fi
  done <<< "$(git ls-tree -r --name-only "$ref")"

  if [ -n "$carrying" ]; then
    status=1
    echo "FAIL $ref carries a Work Context implementation:"
    for path in $carrying; do echo "       $path"; done
  else
    echo "ok   $ref"
  fi
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'

A wire contract has exactly one implementation, in the repository that owns the
type: codefly-dev/core/workcontext. The refs above still sign or verify a Work
Context themselves.

If a ref above is a release line a consumer still pins, this is EXPECTED and the
answer is not to back-port the deletion — that would break the consumer the line
exists for. The answer is to retire the ref once its last consumer has repinned.
docs/cutover.md holds the preconditions and the exact commands, and the deletion
is performed by the repository owner at the cutover, never automatically.

If a ref above is main, a second implementation has been reintroduced. Delete it.
MSG
fi
exit "$status"
