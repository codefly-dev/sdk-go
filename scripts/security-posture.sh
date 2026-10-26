#!/usr/bin/env bash
# The re-runnable check for each security-posture rule this repository owns.
#
# It exists because the catalogue's own commands could not fail. They counted
# lines — `go test … | grep -c '^--- PASS'` — which answers 0 for a PASSING run
# without -v, answers 1 when the parent test is the only unindented record
# whatever its subtests did, and answers 0 for a test that no longer exists at
# all. A check that cannot fail reports green forever, which is worse than no
# check: the invariant stops being audited and nothing says so.
#
# So this reads the EXIT STATUS, and separately requires every named test to
# have actually run. A rule's test being deleted, renamed or filtered out by a
# `-run` pattern that matches nothing is a failure here, not a silent pass.
#
# Usage:
#   scripts/security-posture.sh            # every rule
#   scripts/security-posture.sh SP-WC-01   # one rule
#
# Exit 0 means the rule holds in this repository. Any other exit means it does
# not, or could not be checked.
set -euo pipefail

cd "$(dirname "$0")/.."

# Each rule names the module it is checked in and the tests that check it.
# A test named here must exist and must pass.
sp_wc_01_module="workcontext"
sp_wc_01_tests="TestDerivedContextNeverOutlivesParent"

sp_wc_05_module="workcontext"
sp_wc_05_tests="TestEveryVerificationPathIsPinned
TestNewVerifierRefusesAnIncompleteConfigurationByName
TestNewVerifierRefusesUnusableKeyMaterial
TestResolveKeySetEndpointAdmitsOnlyTheMeshContract
TestMeshProtectedComparesTheAssertionLiterally
TestMeshProtectedRefusesALookupFailureRatherThanReadingItAsAbsence
TestALookupFailureRefusesEveryKeySetEndpoint
TestAcquireKeySetFetchesFromTheAdmittedEndpoint
TestAVerifierHoldsOnlyTheKeysItsEndpointServed
TestNoRefusalEchoesTheURL
TestTheAssertionRefusalDoesNotEchoTheValue"

run_rule() {
	local rule="$1" module="$2" tests="$3"
	local pattern output status=0
	pattern="^($(echo "$tests" | paste -sd'|' -))$"

	echo "== $rule: $(echo "$tests" | wc -l | tr -d ' ') test(s) in ${module:-.}"
	# -v so each test's own record is printed; the exit status is what decides,
	# and the records are what prove the tests were not filtered away.
	if ! output="$( (cd "${module:-.}" && go test -count=1 -v -run "$pattern" ./...) 2>&1 )"; then
		status=1
	fi
	local name
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		if ! grep -qE "^--- PASS: ${name}(/|\$| )" <<<"$output"; then
			echo "FAIL $rule: $name did not run and pass."
			echo "     A rule's test that was renamed, deleted or filtered out is a rule that"
			echo "     stopped being checked. That is the failure this line exists to report."
			status=1
		fi
	done <<<"$tests"
	if [ "$status" -ne 0 ]; then
		echo "$output" | sed -n '/^--- FAIL\|^    --- FAIL\|^FAIL\|^# /p' | head -40
		echo "FAIL $rule"
		return 1
	fi
	echo "ok   $rule"
}

rules="${1:-all}"
failed=0
case "$rules" in
SP-WC-01) run_rule SP-WC-01 "$sp_wc_01_module" "$sp_wc_01_tests" || failed=1 ;;
SP-WC-05) run_rule SP-WC-05 "$sp_wc_05_module" "$sp_wc_05_tests" || failed=1 ;;
all)
	run_rule SP-WC-01 "$sp_wc_01_module" "$sp_wc_01_tests" || failed=1
	run_rule SP-WC-05 "$sp_wc_05_module" "$sp_wc_05_tests" || failed=1
	;;
*)
	echo "unknown rule: $rules (known: SP-WC-01, SP-WC-05, all)" >&2
	exit 2
	;;
esac
exit "$failed"
