package codefly_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A TAG CANNOT BE FIXED, ONLY RETRACTED, and nineteen of them publish the
// second implementation this PR deletes.
//
// The ref sweep covers branches, and a branch carrying the implementation can
// be deleted. `v0.1.65` cannot: `go get sdk-go@v0.1.65` resolves it right now,
// the module proxy has it cached permanently, and nothing anybody does to this
// repository changes what that version contains. An executed review found this
// and it had been missed by every round: the sweep's subject was "every
// published ref" and tags are published refs.
//
// So the rule for a tag is RETRACTED, not clean — the one mechanism Go provides
// for "this published version should not be used". This test is the gate on
// that: every tag that carries the implementation is covered by a retract
// directive in go.mod.
//
// It is measured, by reading each tag's imports, not by matching
// `work_context.go` — a name check is the thing this whole change is about.
func TestEveryPublishedTagCarryingTheImplementationIsRetracted(t *testing.T) {
	tags := localTags(t)
	require.NotEmpty(t, tags,
		"no tags are present in this checkout, so this gate read nothing.\n"+
			"CI fetches them (fetch-depth: 0); a run without them would pass having\n"+
			"looked at nothing, which is the fail-open this repository has fixed five times.")

	rootRetracted := retractedVersions(t, ".")
	reader := importReader(t)

	offendingByTag := offendingPathsByRef(t, reader, tags)

	var rootCarrying, leafCarrying, unretracted []string
	for _, tag := range tags {
		offending := offendingByTag[tag]
		if len(offending) == 0 {
			continue
		}
		// WHICH MODULE OWNS THE FILES, which is the whole of this correction.
		// A path under workcontext/ belongs to the LEAF module at any tag where
		// workcontext/go.mod exists — and from v0.1.66 it does, so the root
		// module's zip for those versions does not contain them and the root's
		// retract directive says nothing about them. A previous revision swept
		// each tag's whole tree and then checked only the root go.mod, which is
		// how nineteen retractions came to include four clean root versions and
		// miss the module that actually carries them.
		leaf := tagHasLeafModule(t, tag)
		byLeaf, byRoot := false, false
		for _, path := range offending {
			if leaf && strings.HasPrefix(path, "workcontext/") {
				byLeaf = true
				continue
			}
			byRoot = true
		}
		if byRoot {
			rootCarrying = append(rootCarrying, tag)
			if !rootRetracted[tag] {
				unretracted = append(unretracted, tag+" (root module)")
			}
		}
		if byLeaf {
			// THE LEAF'S INTERVAL IS THE LEAF'S OWN TEST TO ASSERT, and this
			// is where a correction belongs. This used to read the retract
			// bound's TIMESTAMP out of the High field and compare it as a
			// string — which cannot see an interval whose LOW bound is above
			// its high, and that is exactly the state it passed over: the leaf
			// retraction was `[v0.0.0, v0.0.0-…]`, which covers no version at
			// all, because a prerelease sorts below its release.
			//
			// A hand comparison of one bound is how that went unnoticed, so
			// the question moved to workcontext's own
			// TestTheRetractIntervalCoversThePublishedVersions, which asks
			// golang.org/x/mod/semver — Go's implementation of the ordering —
			// whether the interval is non-empty and covers every carrying
			// pseudo-version. What is recorded here is only that this tag's
			// files belong to the LEAF module, which is the fact this test can
			// establish.
			leafCarrying = append(leafCarrying, tag)
		}
	}

	require.NotEmpty(t, rootCarrying,
		"no tag carries the implementation in the ROOT module, which contradicts the "+
			"measurement this gate was written from")
	require.NotEmpty(t, leafCarrying,
		"no tag carries it in the LEAF module either, and from v0.1.66 the files live there — "+
			"so either the classification is broken or the sweep is")
	require.Empty(t, unretracted,
		"these published versions carry a second Work Context implementation and are not "+
			"retracted: %v.\nA consumer can pin any of them today. A tag cannot be deleted or "+
			"fixed, so the only answer is a retract directive in the go.mod of the module that "+
			"OWNS the files — which takes effect once a new version of that module is tagged.",
		unretracted)
}

// tagHasLeafModule reports whether workcontext/ was its own module at a tag.
func tagHasLeafModule(t *testing.T, tag string) bool {
	t.Helper()
	run := exec.Command("git", "cat-file", "-e", tag+":workcontext/go.mod")
	return run.Run() == nil
}

// offendingPathsByRef runs the repository sweep ONCE over every tag and returns
// the paths it reported, by ref.
//
// One invocation, not one per tag. Per-tag it was 333 seconds for 83 tags —
// each spawning the script, which parses the policy, builds its allow lists and
// shells out per file — and CI's job timeout is five minutes. A gate that
// cannot finish inside the job is a gate somebody deletes. The script already
// loops over its arguments and reports `ok <ref>` or `FAIL <ref> …`, so this is
// a parse of what it was always printing.
func offendingPathsByRef(t *testing.T, reader string, tags []string) map[string][]string {
	t.Helper()
	run := exec.Command("bash", append([]string{"scripts/check-one-implementation.sh"}, tags...)...)
	run.Env = append(sweepEnv(t), "IMPORTSOF_BIN="+reader)
	output, _ := run.CombinedOutput()

	byRef := map[string][]string{}
	current := ""
	for _, line := range strings.Split(string(output), "\n") {
		switch {
		case strings.HasPrefix(line, "FAIL ") && strings.Contains(line, "carries a Work Context"):
			current = strings.TrimSpace(strings.TrimSuffix(
				strings.TrimPrefix(line, "FAIL "), " carries a Work Context implementation:"))
			byRef[current] = nil
		case strings.HasPrefix(line, "ok   "):
			current = ""
		case current != "" && strings.HasPrefix(line, "       "):
			path, _, found := strings.Cut(strings.TrimSpace(line), " imports ")
			if found && strings.HasSuffix(path, ".go") {
				byRef[current] = append(byRef[current], path)
			}
		}
	}
	// EVERY TAG MUST HAVE BEEN REPORTED ON, or the parse is reading less than
	// the sweep said and a tag could be silently clean.
	reported := len(byRef)
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "ok   ") {
			reported++
		}
	}
	require.GreaterOrEqual(t, reported, len(tags),
		"the sweep reported on %d of %d tags; a tag it did not reach is a tag this gate "+
			"cleared without looking:\n%s", reported, len(tags), output)
	return byRef
}

// localTags is every tag in this checkout, which in CI is every published tag.
func localTags(t *testing.T) []string {
	t.Helper()
	run := exec.Command("git", "tag")
	output, err := run.Output()
	require.NoError(t, err)
	var tags []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" {
			tags = append(tags, line)
		}
	}
	return tags
}

// retractedVersions expands go.mod's retract directives, ranges included.
//
// Read through `go mod edit -json` rather than by matching the file, because
// the shape a person writes and the set the go tool acts on are two different
// things — and this gate is about the second.
type retractSpan struct {
	Low  string `json:"Low"`
	High string `json:"High"`
}

// retractSpans reads one module's retract directives through `go mod edit
// -json`, because the shape a person writes and the set the go tool acts on are
// two different things and this gate is about the second.
func retractSpans(t *testing.T, dir string) []retractSpan {
	t.Helper()
	run := exec.Command("go", "mod", "edit", "-json")
	run.Dir = dir
	output, err := run.Output()
	require.NoError(t, err)

	var parsed struct {
		Retract []retractSpan `json:"Retract"`
	}
	require.NoError(t, json.Unmarshal(output, &parsed))
	return parsed.Retract
}

func retractedVersions(t *testing.T, dir string) map[string]bool {
	t.Helper()
	spans := retractSpans(t, dir)
	require.NotEmpty(t, spans, "%s/go.mod retracts nothing", dir)

	covered := map[string]bool{}
	for _, tag := range localTags(t) {
		for _, span := range spans {
			// `go mod edit -json` writes a single version as Low == High, so
			// one comparison covers both shapes.
			if semverAtMost(t, span.Low, tag) && semverAtMost(t, tag, span.High) {
				covered[tag] = true
			}
		}
	}
	return covered
}

// semverAtMost reports whether low <= high, for PLAIN RELEASE VERSIONS ONLY.
//
// It refuses a prerelease rather than ordering one, and that guard is the
// lesson from the leaf module's empty interval: a prerelease sorts BELOW its
// release, a hand comparison that does not know this reads `[v0.0.0,
// v0.0.0-…]` as a sensible range, and the interval covered nothing. The root
// module's tags and retract bounds are all plain `vX.Y.Z`, so this is enough
// here — and if that ever stops being true, this fails instead of guessing.
//
// The leaf module's own interval, which IS pseudo-versions, is asserted by
// workcontext's TestTheRetractIntervalCoversThePublishedVersions using
// golang.org/x/mod/semver. One hand-rolled ordering in this repository is one
// too many; this one is bounded to the case it is correct for.
func semverAtMost(t *testing.T, low string, high string) bool {
	t.Helper()
	require.NoError(t, comparableVersions(low, high))
	return low == high || compareVersions(low, high) <= 0
}

// comparableVersions reports whether this comparison may be made at all.
//
// Separated from the comparison so a probe can drive it: asserted only through
// semverAtMost, a mutation that removed the guard changed nothing, because the
// root module's tags and bounds are all plain releases and no test ever passed
// a prerelease. A guard no test can reach is a guard nobody has checked, which
// is the shape that let the empty interval through in the first place.
func comparableVersions(versions ...string) error {
	for _, version := range versions {
		if strings.Contains(version, "-") {
			return fmt.Errorf(
				"%q carries a prerelease and this comparison cannot order one: a prerelease "+
					"sorts BELOW its release, which is how an empty retract interval read as a "+
					"range. Use golang.org/x/mod/semver, as workcontext does", version)
		}
	}
	return nil
}

// compareVersions orders vMAJOR.MINOR.PATCH numerically. Both inputs come from
// this repository's own tags and its own go.mod, which are all of that shape.
func compareVersions(left string, right string) int {
	leftParts := versionFields(left)
	rightParts := versionFields(right)
	for index := range 3 {
		switch {
		case leftParts[index] < rightParts[index]:
			return -1
		case leftParts[index] > rightParts[index]:
			return 1
		}
	}
	return 0
}

// versionFields parses the three numeric fields. A field that is not a number
// becomes -1, which orders before everything — so a tag this repository does
// not use the shape of sorts outside every retract range and is REPORTED as
// unretracted rather than silently covered by one.
func versionFields(version string) [3]int {
	var fields [3]int
	trimmed := strings.TrimPrefix(version, "v")
	for index, part := range strings.SplitN(trimmed, ".", 3) {
		if index > 2 {
			break
		}
		value := 0
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				value = -1
				break
			}
			value = value*10 + int(digit-'0')
		}
		fields[index] = value
	}
	return fields
}

// THE HISTORICAL ALLOWANCE CANNOT BECOME THE HOLE THE DENYLIST WAS.
//
// `legacy` lines in the import policy apply only when sweeping a published ref,
// because deny-by-default describes today's tree and two years of tags
// legitimately import things this repository has stopped using — the first run
// over history flagged 33 clean tags for a renamed core package and a Postgres
// driver. That allowance is measured, and this is what keeps it honest: not one
// entry may be a signature, a MAC, an envelope or a token library, because those
// are the whole subject of the rule it relaxes.
func TestTheHistoricalImportAllowanceCarriesNothingCapabilityShaped(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("scripts", "allowed-imports.txt"))
	require.NoError(t, err)

	var legacy []string
	for _, line := range strings.Split(string(raw), "\n") {
		if module, path, found := strings.Cut(strings.TrimSpace(line), " "); found && module == "legacy" {
			legacy = append(legacy, path)
		}
	}
	require.NotEmpty(t, legacy, "the allowance is empty, so this test asserts nothing")

	// The capability-shaped fragments, which is the same question the old
	// denylist asked — kept here, where it is the right question, rather than
	// in the sweep, where it was the only one.
	for _, path := range legacy {
		lowered := strings.ToLower(path)
		for _, fragment := range []string{
			"crypto", "jose", "jwt", "jwx", "paseto", "macaroon", "branca",
			"base64", "base32", "ascii85", "pem", "protojson", "protowire",
			"protodelim", "protoiface", "protoimpl", "anypb", "json", "mime",
			"gob", "asn1", "xml", "mldsa", "ed25519", "hkdf", "pbkdf2",
		} {
			require.NotContains(t, lowered, fragment,
				"the historical allowance lists %q, which contains %q. That allowance exists "+
					"for a renamed core package and a database driver; a signature, a MAC, an "+
					"envelope or a token library in it would reopen exactly the hole "+
					"deny-by-default was adopted to close.", path, fragment)
		}
	}
}

// THE ORDERING GUARD, driven at the predicate.
//
// This repository's hand-rolled version comparison is bounded to plain releases
// on purpose, and the bound is the lesson from the leaf module's retract
// interval: `[v0.0.0, v0.0.0-20261004000000-zzzzzzzzzzzz]` covers NO version,
// because a prerelease sorts below its release — and a hand comparison that did
// not know that read it as a sensible range for a whole commit.
//
// So this refuses rather than guesses, and the refusal is tested, because a
// mutation that removed it left every test green: the root's tags and bounds
// are all plain releases, so nothing ever reached the guard.
func TestTheVersionComparisonRefusesWhatItCannotOrder(t *testing.T) {
	for name, version := range map[string]string{
		"a pseudo-version":    "v0.0.0-20261004000000-zzzzzzzzzzzz",
		"a release candidate": "v1.0.0-rc.1",
		"the zero prerelease": "v0.0.0-0",
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, comparableVersions("v0.1.51", version))
			require.Error(t, comparableVersions(version, "v0.1.51"))
			require.ErrorContains(t, comparableVersions(version),
				"sorts BELOW its release",
				"the refusal must say WHY, because the reader's next move is to compare it anyway")
		})
	}

	// Plain releases are comparable, so the guard is not refusing everything —
	// and the ordering it then performs is the one the retract check relies on.
	require.NoError(t, comparableVersions("v0.1.51", "v0.1.65", "v0.2.0"))
	require.True(t, semverAtMost(t, "v0.1.51", "v0.1.65"))
	require.True(t, semverAtMost(t, "v0.1.65", "v0.1.65"))
	require.False(t, semverAtMost(t, "v0.2.0", "v0.1.65"))
}
