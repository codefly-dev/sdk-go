package codefly_test

import (
	"encoding/json"
	"os/exec"
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
			"CI fetches them (`git fetch --tags`); a run without them would pass having\n"+
			"looked at nothing, which is the fail-open this repository has fixed five times.")

	retracted := retractedVersions(t)
	reader := importReader(t)

	var carrying, unretracted []string
	for _, tag := range tags {
		if !tagCarriesAnImplementation(t, reader, tag) {
			continue
		}
		carrying = append(carrying, tag)
		if !retracted[tag] {
			unretracted = append(unretracted, tag)
		}
	}

	require.NotEmpty(t, carrying,
		"not one published tag carries the implementation, which contradicts the measurement "+
			"this gate was written from — so the measurement is now wrong or the sweep is")
	require.Empty(t, unretracted,
		"these published versions carry a second Work Context implementation and are not "+
			"retracted: %v.\nA consumer can pin any of them today. A tag cannot be deleted or "+
			"fixed, so the only answer is a retract directive in go.mod — which takes effect "+
			"once a new version is tagged carrying it.", unretracted)
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
func retractedVersions(t *testing.T) map[string]bool {
	t.Helper()
	run := exec.Command("go", "mod", "edit", "-json")
	output, err := run.Output()
	require.NoError(t, err)

	var parsed struct {
		Retract []struct {
			Low  string `json:"Low"`
			High string `json:"High"`
		} `json:"Retract"`
	}
	require.NoError(t, json.Unmarshal(output, &parsed))
	require.NotEmpty(t, parsed.Retract, "go.mod retracts nothing")

	covered := map[string]bool{}
	for _, tag := range localTags(t) {
		for _, span := range parsed.Retract {
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

// tagCarriesAnImplementation runs the repository sweep over one tag.
func tagCarriesAnImplementation(t *testing.T, reader string, tag string) bool {
	t.Helper()
	run := exec.Command("bash", "scripts/check-one-implementation.sh", tag)
	run.Env = append(sweepEnv(t), "IMPORTSOF_BIN="+reader)
	output, err := run.CombinedOutput()
	if err == nil {
		return false
	}
	require.Contains(t, string(output), "carries a Work Context implementation",
		"the sweep failed on %s for a reason that is not a finding:\n%s", tag, output)
	return true
}
