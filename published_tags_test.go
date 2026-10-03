package codefly_test

import (
	"encoding/json"
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
	leafBound := leafRetractBound(t)
	reader := importReader(t)

	var rootCarrying, leafCarrying, unretracted []string
	for _, tag := range tags {
		offending := offendingPathsAt(t, reader, tag)
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
			leafCarrying = append(leafCarrying, tag)
			// The leaf module has never been tagged, so there is no leaf
			// version to name: what a consumer resolves is a pseudo-version of
			// the commit. The leaf retract covers a RANGE up to a timestamp,
			// so the question is whether this tag's commit falls inside it.
			if stamp := commitStamp(t, tag); stamp > leafBound {
				unretracted = append(unretracted,
					tag+" (leaf module, commit "+stamp+" is past the retract bound "+leafBound+")")
			}
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

// commitStamp is a tag's commit time in a pseudo-version's own format, so it
// compares against a retract bound as a string the way the go tool orders them.
func commitStamp(t *testing.T, tag string) string {
	t.Helper()
	run := exec.Command("git", "log", "-1", "--format=%cd",
		"--date=format:%Y%m%d%H%M%S", tag)
	output, err := run.Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

// leafRetractBound is the timestamp inside the leaf module's retract high
// bound. A leaf go.mod with no retract is a finding, loudly, because that is
// the state this correction found.
func leafRetractBound(t *testing.T) string {
	t.Helper()
	spans := retractSpans(t, "workcontext")
	require.NotEmpty(t, spans,
		"workcontext/go.mod retracts nothing, and it is the module that carries the "+
			"implementation from root tag v0.1.66 onward")
	var highest string
	for _, span := range spans {
		_, stamp, found := strings.Cut(span.High, "-")
		require.True(t, found,
			"the leaf retract bound %q is not a pseudo-version; this module has never been "+
				"tagged, so a range of pseudo-versions is what covers its published versions",
			span.High)
		stamp, _, _ = strings.Cut(stamp, "-")
		if stamp > highest {
			highest = stamp
		}
	}
	return highest
}

// offendingPathsAt runs the repository sweep over one tag and returns the paths
// it reported.
func offendingPathsAt(t *testing.T, reader string, tag string) []string {
	t.Helper()
	run := exec.Command("bash", "scripts/check-one-implementation.sh", tag)
	run.Env = append(sweepEnv(t), "IMPORTSOF_BIN="+reader)
	output, err := run.CombinedOutput()
	if err == nil {
		return nil
	}
	require.Contains(t, string(output), "carries a Work Context implementation",
		"the sweep failed on %s for a reason that is not a finding:\n%s", tag, output)
	var paths []string
	for _, line := range strings.Split(string(output), "\n") {
		path, _, found := strings.Cut(strings.TrimSpace(line), " imports ")
		if found && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
	}
	require.NotEmpty(t, paths, "the sweep reported a finding and named no file:\n%s", output)
	return paths
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
			if semverAtMost(span.Low, tag) && semverAtMost(tag, span.High) {
				covered[tag] = true
			}
		}
	}
	return covered
}

// semverAtMost reports whether low <= high.
func semverAtMost(low string, high string) bool {
	return low == high || compareVersions(low, high) <= 0
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
