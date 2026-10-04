package workcontext

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
)

// THE RETRACT INTERVAL IS NON-EMPTY AND COVERS WHAT IT CLAIMS TO.
//
// The first attempt at this module's retraction wrote
//
//	retract [v0.0.0, v0.0.0-20261004000000-zzzzzzzzzzzz]
//
// which covers NOTHING. Under semver a prerelease sorts BELOW its release, so
// `v0.0.0-2026…` is LESS than `v0.0.0`: the interval has low > high and is
// empty, and every published pseudo-version of this module sat outside a
// declaration that read as though it covered all of them. `go mod edit -json`
// printed it back without complaint, `go build` and `go vet` passed, and the
// root module's check compared the bound's TIMESTAMP as a string — so the one
// thing nobody asked was whether the interval contained anything.
//
// That is the fail-open shape this repository has now produced six times: a
// declaration that looks like a gate. The pattern in all six is the same — the
// check was written in terms of the thing's spelling rather than its meaning.
//
// So the ordering is answered by golang.org/x/mod/semver, which is Go's own
// implementation of it and the same one `go list -m -retracted` uses. A hand
// comparison is what missed it.
func TestTheRetractIntervalCoversThePublishedVersions(t *testing.T) {
	spans := ownRetractSpans(t)
	require.NotEmpty(t, spans,
		"this module carries the implementation from root tag v0.1.66 onward and must retract "+
			"the versions that publish it")

	for _, span := range spans {
		require.True(t, semver.IsValid(span.Low), "retract low bound %q is not a version", span.Low)
		require.True(t, semver.IsValid(span.High), "retract high bound %q is not a version", span.High)
		require.LessOrEqual(t, semver.Compare(span.Low, span.High), 0,
			"retract [%s, %s] is EMPTY: low sorts above high, so it covers no version at all. "+
				"A prerelease sorts BELOW its release, so [v0.0.0, v0.0.0-…] is the mistake this "+
				"test exists for.", span.Low, span.High)
	}

	// EVERY PUBLISHED VERSION THAT CARRIES IT, by pseudo-version, computed from
	// the commits rather than written down — a list of versions in a test is
	// another thing that can silently stop matching what is published.
	carrying := carryingPseudoVersions(t)
	require.NotEmpty(t, carrying,
		"no commit in this checkout carries the implementation under workcontext/, which "+
			"contradicts the measurement this retraction was written from")
	t.Logf("%d published version(s) of this module carry the implementation", len(carrying))

	for _, version := range carrying {
		covered := false
		for _, span := range spans {
			if semver.Compare(version, span.Low) >= 0 && semver.Compare(version, span.High) <= 0 {
				covered = true
				break
			}
		}
		require.True(t, covered,
			"%s publishes this module WITH the second implementation and no retract interval "+
				"covers it. A consumer resolves it today; a tag cannot be fixed, only retracted.",
			version)
	}

	// And a version from after the bound is NOT retracted, so the interval is
	// not simply swallowing everything — which would make the assertion above
	// pass for the wrong reason and would retract this PR's own release.
	future := "v0.0.0-20991231235959-ffffffffffff"
	for _, span := range spans {
		require.Positive(t, semver.Compare(future, span.High),
			"the retraction covers %s, which is later than every carrying commit — an interval "+
				"that retracts the fix as well as the defect is not a retraction", future)
	}
}

type ownRetractSpan struct {
	Low  string
	High string
}

// ownRetractSpans reads this module's own retract directives through the go
// tool, because the shape a person writes and the set the tool acts on are two
// different things.
func ownRetractSpans(t *testing.T) []ownRetractSpan {
	t.Helper()
	run := exec.Command("go", "mod", "edit", "-json")
	output, err := run.Output()
	require.NoError(t, err)
	var parsed struct {
		Retract []ownRetractSpan
	}
	require.NoError(t, json.Unmarshal(output, &parsed))
	return parsed.Retract
}

// carryingPseudoVersions is the pseudo-version of every commit whose
// workcontext/ tree carries the deleted implementation.
//
// Computed from git rather than listed, and it reads the commit's own timestamp
// in UTC, which is what the go tool puts in a pseudo-version.
func carryingPseudoVersions(t *testing.T) []string {
	t.Helper()
	// THE LEAF PATHS. The first version of this asked git for `work_context.go`
	// — the ROOT-level file, which belongs to the root module — so it asserted
	// about nine commits of the wrong module's history and passed. The files
	// this module publishes are under workcontext/.
	run := exec.Command("git", "log", "--format=%H %cd",
		"--date=format-local:%Y%m%d%H%M%S", "--all", "--",
		"workcontext/work_context.go", "workcontext/work_context_jwks.go")
	run.Dir = ".."
	run.Env = append(os.Environ(), "TZ=UTC")
	output, err := run.Output()
	require.NoError(t, err)

	var versions []string
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		sha, stamp, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found || len(sha) < 12 {
			continue
		}
		// A commit that TOUCHED the path includes the one that DELETED it, and
		// a commit where the file is absent does not publish it. `git log
		// -- path` cannot tell those apart, so the tree is asked.
		if !blobExistsAt(t, sha, "workcontext/work_context.go") &&
			!blobExistsAt(t, sha, "workcontext/work_context_jwks.go") {
			continue
		}
		version := "v0.0.0-" + stamp + "-" + sha[:12]
		if !seen[version] {
			seen[version] = true
			versions = append(versions, version)
		}
	}
	return versions
}

func blobExistsAt(t *testing.T, sha string, path string) bool {
	t.Helper()
	run := exec.Command("git", "cat-file", "-e", sha+":"+path)
	run.Dir = ".."
	return run.Run() == nil
}
