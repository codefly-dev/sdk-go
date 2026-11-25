package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// repository creates a git repository holding files, all tracked, and returns
// its directory.
func repository(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	for path, content := range files {
		write(t, dir, path, content)
	}
	git(t, dir, "add", "-A")
	return dir
}

func write(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(path))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
}

func git(t *testing.T, dir string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, arguments...)...)
	// The repository under test must not read the developer's or the
	// enclosing checkout's configuration.
	command.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "git %v: %s", arguments, output)
}

// guard runs the command and returns its exit status and both streams.
func guard(arguments ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	status := run(arguments, &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

func TestRunPassesACleanRepository(t *testing.T) {
	dir := repository(t, map[string]string{
		"main.go":      "package main\n\nvar listen = \"127.0.0.1:0\"\n",
		"main_test.go": "package main\n\nvar unreachable = \"http://127.0.0.1:1\"\n",
		"README.md":    "Resolve the address with `codefly endpoint mod/svc --type http`.\n",
	})
	status, stdout, stderr := guard(dir)
	require.Equal(t, exitClean, status, stdout+stderr)
	require.Equal(t, "netguard: 0 violations (runtime 0, test 0, doc 0), 0 unused allow-list entries\n", stdout)
	require.Empty(t, stderr)
}

func TestRunFailsOnAViolationAndSaysWhereAndHowToFixIt(t *testing.T) {
	dir := repository(t, map[string]string{
		"pkg/client.go":      "package pkg\n\nconst base = \"http://localhost:2532\"\n",
		"pkg/client_test.go": "package pkg\n\nconst dsn = \"postgres://postgres:example@127.0.0.1:5432/postgres\"\n",
		"Dockerfile":         "FROM scratch\nEXPOSE 8092\n",
		"docs/run.md":        "Open localhost:3000.\n",
	})
	status, stdout, _ := guard(dir)
	require.Equal(t, exitViolation, status)
	for _, line := range []string{
		"Dockerfile:2: 8092\t[port, runtime]\n",
		"docs/run.md:1: localhost:3000\t[hostport, doc]\n",
		"pkg/client.go:3: http://localhost:2532\t[url, runtime]\n",
		"pkg/client_test.go:3: postgres://postgres:example@127.0.0.1:5432/postgres\t[dsn, test]\n",
		"fix dsn: read the connection from the SDK",
		"fix hostport: resolve the address through the SDK",
		"fix port: take the port from the service's own endpoint",
		"fix url: resolve the URL through the SDK",
		"netguard: 4 violations (runtime 2, test 1, doc 1), 0 unused allow-list entries\n",
	} {
		require.Contains(t, stdout, line)
	}

	// -summary prints the counts and nothing else, and still fails.
	status, stdout, _ = guard("-summary", dir)
	require.Equal(t, exitViolation, status)
	require.Equal(t, "netguard: 4 violations (runtime 2, test 1, doc 1), 0 unused allow-list entries\n", stdout)
}

func TestRunReadsTrackedFilesOnly(t *testing.T) {
	dir := repository(t, map[string]string{"main.go": "package main\n"})
	// Written after `git add`: untracked, so it ships to nobody.
	write(t, dir, "local.env", "API=http://localhost:8080\n")
	status, stdout, stderr := guard(dir)
	require.Equal(t, exitClean, status, stdout+stderr)

	// Once tracked, the same file is a finding — and it is the working-tree
	// content that is read, so an edit after `git add` is seen too.
	git(t, dir, "add", "local.env")
	write(t, dir, "main.go", "package main\n\nconst port = 9090\n")
	status, stdout, _ = guard(dir)
	require.Equal(t, exitViolation, status)
	require.Contains(t, stdout, "local.env:1: http://localhost:8080")
	require.Contains(t, stdout, "main.go:3: 9090")
}

func TestRunSkipsWhatIsNotSourceText(t *testing.T) {
	dir := repository(t, map[string]string{
		"main.go":                    "package main\n",
		"node_modules/x/index.js":    "const a = 'localhost:8080'\n",
		"dist/index.js":              "const a = 'localhost:8080'\n",
		"go.sum":                     "port: 8080\n",
		"api/service.pb.go":          "// localhost:8080\n",
		"image.bin":                  "\x00\x01localhost:8080\n",
		"removed-from-worktree.conf": "listen localhost:8080\n",
	})
	require.NoError(t, os.Symlink("/nonexistent/localhost:8080", filepath.Join(dir, "link")))
	git(t, dir, "add", "link")
	require.NoError(t, os.Remove(filepath.Join(dir, "removed-from-worktree.conf")))

	status, stdout, stderr := guard(dir)
	require.Equal(t, exitClean, status, stdout+stderr)
}

func TestRunAppliesTheAllowListAndNeverScansIt(t *testing.T) {
	files := map[string]string{
		"templates/service.yaml.tmpl": "      port: 8080\n",
		"pkg/oauth_test.go":           "package pkg\n\nconst redirect = \"http://localhost:54321/callback\"\n",
		"docs/run.md":                 "Open localhost:3000 or localhost:3001.\n",
		"deployments/local/svc.yaml":  "      port: 9090\n      targetPort: 9090\n",
		"scripts/networking.allow": "# class\tpath-glob\tliteral\treason\n" +
			"agent\ttemplates/**\t8080\tthe standard REST port\n" +
			"vector\tpkg/*_test.go\thttp://localhost:54321\tOAuth loopback redirect under test\n" +
			"doc\tdocs/**\t*\tprose\n" +
			"exclude\tdeployments/**\t*\trendered by codefly\n",
	}
	dir := repository(t, files)
	status, stdout, stderr := guard(dir)
	require.Equal(t, exitClean, status, stdout+stderr)

	// The same tree with no list: every one of those is a finding, and the
	// excluded path is read.
	require.NoError(t, os.Remove(filepath.Join(dir, "scripts", "networking.allow")))
	git(t, dir, "add", "-A")
	status, stdout, _ = guard(dir)
	require.Equal(t, exitViolation, status)
	require.Contains(t, stdout, "netguard: 6 violations (runtime 3, test 1, doc 2), 0 unused allow-list entries\n")
	require.Contains(t, stdout, "deployments/local/svc.yaml:1: 9090")
}

func TestRunFailsOnAnAllowListEntryThatCoversNothing(t *testing.T) {
	dir := repository(t, map[string]string{
		"templates/service.yaml.tmpl": "      port: {{ .HTTPPort }}\n",
		"scripts/networking.allow": "agent\ttemplates/**\t8080\tthe standard REST port\n" +
			"exclude\tdeployments/**\t*\trendered by codefly\n",
	})
	status, stdout, _ := guard(dir)
	require.Equal(t, exitViolation, status)
	require.Contains(t, stdout, "scripts/networking.allow:1: allow-list entry covers nothing: agent templates/** 8080\n")
	require.Contains(t, stdout, "scripts/networking.allow:2: allow-list entry covers nothing: exclude deployments/** *\n")
	require.Contains(t, stdout, "netguard: 0 violations (runtime 0, test 0, doc 0), 2 unused allow-list entries\n")
}

func TestRunRefusesAVectorOutsideATest(t *testing.T) {
	dir := repository(t, map[string]string{
		"pkg/oauth.go":             "package pkg\n\nconst redirect = \"http://localhost:54321/callback\"\n",
		"scripts/networking.allow": "vector\tpkg/**\thttp://localhost:54321\tredirect under test\n",
	})
	status, stdout, _ := guard(dir)
	require.Equal(t, exitViolation, status)
	require.Contains(t, stdout, "pkg/oauth.go:3: http://localhost:54321\t[url, runtime]\n")
	require.Contains(t, stdout, "allow-list entry covers nothing: vector pkg/** http://localhost:54321\n")
}

func TestRunTakesAnAllowListByFlag(t *testing.T) {
	dir := repository(t, map[string]string{
		"templates/service.yaml.tmpl": "      port: 8080\n",
		"guard/net.allow":             "agent\ttemplates/**\t8080\tthe standard REST port\n",
	})
	for _, arguments := range [][]string{
		{"-allow", "guard/net.allow", dir},
		{"--allow=guard/net.allow", dir},
		{dir, "-allow", filepath.Join(dir, "guard", "net.allow")},
	} {
		status, stdout, stderr := guard(arguments...)
		require.Equal(t, exitClean, status, strings.Join(arguments, " ")+"\n"+stdout+stderr)
	}

	// Without the flag the default list is absent, so the port is a finding.
	status, _, _ := guard(dir)
	require.Equal(t, exitViolation, status)
}

func TestRunDefaultsToTheCurrentDirectory(t *testing.T) {
	dir := repository(t, map[string]string{"main.go": "package main\n\nconst port = 8080\n"})
	t.Chdir(dir)
	status, stdout, _ := guard()
	require.Equal(t, exitViolation, status)
	require.Contains(t, stdout, "main.go:3: 8080\t[port, runtime]\n")
}

func TestRunCannotRun(t *testing.T) {
	dir := repository(t, map[string]string{
		"main.go":      "package main\n",
		"broken.allow": "not an allow-list\n",
	})
	for name, tc := range map[string]struct {
		arguments []string
		want      string
	}{
		"an unknown flag":               {[]string{"-verbose", dir}, "unknown flag -verbose"},
		"a flag with no value":          {[]string{dir, "-allow"}, "-allow needs a file"},
		"an empty flag value":           {[]string{"-allow=", dir}, "-allow needs a file"},
		"a value on a switch":           {[]string{"-summary=yes", dir}, "-summary takes no value"},
		"two directories":               {[]string{dir, dir}, "one directory at most, got 2"},
		"a named list that is missing":  {[]string{"-allow", "absent.allow", dir}, "read allow-list"},
		"a list that does not parse":    {[]string{"-allow", "broken.allow", dir}, "line 1: want four tab-separated fields"},
		"a directory git does not know": {[]string{filepath.Join(t.TempDir(), "absent")}, "git ls-files in"},
	} {
		t.Run(name, func(t *testing.T) {
			status, stdout, stderr := guard(tc.arguments...)
			require.Equal(t, exitUnusable, status)
			require.Empty(t, stdout)
			require.Contains(t, stderr, "netguard: ")
			require.Contains(t, stderr, tc.want)
		})
	}
}

// The tool holds its own repository to the rule, under `go test ./...`: a
// literal added anywhere in sdk-go is a finding here before it is one in CI,
// and an entry of scripts/networking.allow that no longer covers anything
// fails the same way.
func TestThisRepositoryHoldsTheRule(t *testing.T) {
	status, stdout, stderr := guard(filepath.Join("..", ".."))
	require.Equal(t, exitClean, status, stdout+stderr)
}
