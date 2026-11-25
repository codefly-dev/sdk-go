package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAllowListReadsTheDocumentedFormat(t *testing.T) {
	list, err := parseAllowList("# class\tpath-glob\tliteral\treason\n" +
		"\n" +
		"vector\tpkg/auth/*_test.go\thttp://localhost:54321\tOAuth loopback redirect under test\n" +
		"protocol\tgitops.go\t15008\tIstio ambient HBONE port\r\n" +
		"agent\t\ttemplates/deployment/**\t\t8080\tstandards.Port(rest)\n" +
		"doc\tdocs/**\t*\tprose\n" +
		"exclude\tdeployments/**\t*\trendered by codefly\n")
	require.NoError(t, err)
	require.Len(t, list.entries, 5)
	require.Equal(t, allowEntry{line: 3, class: "vector", glob: "pkg/auth/*_test.go", literal: "http://localhost:54321", reason: "OAuth loopback redirect under test"}, *list.entries[0])
	// Runs of tabs align columns and a CRLF file reads the same.
	require.Equal(t, allowEntry{line: 4, class: "protocol", glob: "gitops.go", literal: "15008", reason: "Istio ambient HBONE port"}, *list.entries[1])
	require.Equal(t, allowEntry{line: 5, class: "agent", glob: "templates/deployment/**", literal: "8080", reason: "standards.Port(rest)"}, *list.entries[2])
}

func TestParseAllowListRefusesWhatItCannotHold(t *testing.T) {
	for name, tc := range map[string]struct{ content, want string }{
		"spaces instead of tabs":    {"doc docs/** * prose\n", "line 1: want four tab-separated fields"},
		"a missing reason":          {"doc\tdocs/**\t*\n", "line 1: want four tab-separated fields"},
		"an unknown class":          {"# header\nbaseline\tpkg/**\tlocalhost:8080\tlater\n", `line 2: unknown class "baseline"`},
		"a wildcard for a vector":   {"vector\tpkg/**\t*\teverything\n", "line 1: * as the literal is accepted for doc and exclude only, not for vector"},
		"a wildcard for an agent":   {"agent\ttemplates/**\t*\teverything\n", "not for agent"},
		"an exclude with a literal": {"exclude\tdeployments/**\t8080\trendered\n", "line 1: an exclude entry removes whole paths"},
		"a malformed glob":          {"doc\tdocs/[\t*\tprose\n", `line 1: malformed path glob "docs/["`},
		"the same entry twice":      {"doc\tdocs/**\t*\tprose\n\ndoc\tdocs/**\t*\tprose again\n", "line 3: repeats line 1"},
		"a fifth field":             {"doc\tdocs/**\t*\tprose\textra\n", "got 5"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseAllowList(tc.content)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestAllowListCoversByClassPathAndExactLiteral(t *testing.T) {
	list, err := parseAllowList("" +
		"vector\tpkg/**\thttp://localhost:54321\tredirect under test\n" +
		"agent\ttemplates/**\t8080\tthe standard port\n" +
		"doc\tdocs/**\t*\tprose\n" +
		"doc\tREADME.md\tlocalhost:8080\tthe quick start\n" +
		"exclude\tdeployments/**\t*\trendered\n" +
		"external\tpkg/**\thttps://api.partner.com:8443\ta partner's fixed address\n")
	require.NoError(t, err)

	hit := func(path, class, literal string) finding {
		return finding{path: path, line: 1, class: class, literal: literal, kind: kindOf(path)}
	}

	require.True(t, list.covers(hit("templates/deployment/service.yaml.tmpl", classPort, "8080")))
	// The literal is exact: another port in the same file is not covered.
	require.False(t, list.covers(hit("templates/deployment/service.yaml.tmpl", classPort, "9090")))
	// The path is part of the entry: the same port elsewhere is not covered.
	require.False(t, list.covers(hit("pkg/server.go", classPort, "8080")))

	// A vector is a value under test: covered in a test, refused in shipped
	// code even though the glob and the literal match.
	require.True(t, list.covers(hit("pkg/auth/oauth_test.go", classURL, "http://localhost:54321")))
	require.False(t, list.covers(hit("pkg/auth/oauth.go", classURL, "http://localhost:54321")))

	// `*` covers every literal under the glob, for doc.
	require.True(t, list.covers(hit("docs/running.md", classHostPort, "localhost:3000")))
	require.True(t, list.covers(hit("docs/deep/er.md", classDSN, "postgres://u@h/db")))
	require.True(t, list.covers(hit("README.md", classHostPort, "localhost:8080")))
	require.False(t, list.covers(hit("README.md", classHostPort, "localhost:9090")))

	// An exclude entry removes paths and covers no finding by itself.
	require.True(t, list.excludes("deployments/local/service.yaml"))
	require.False(t, list.excludes("pkg/server.go"))
	require.False(t, list.covers(hit("deployments/local/service.yaml", classPort, "8080")))

	// Everything above was used except the external entry.
	unused := list.unused()
	require.Len(t, unused, 1)
	require.Equal(t, "external", unused[0].class)
	require.Equal(t, 6, unused[0].line)
}

func TestLoadAllowListMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "scripts", "networking.allow")

	// The default list may be absent: a repository with nothing to allow has
	// no file to keep.
	list, err := loadAllowList(missing, false)
	require.NoError(t, err)
	require.Empty(t, list.entries)

	// A list the caller named must be there.
	_, err = loadAllowList(missing, true)
	require.ErrorIs(t, err, os.ErrNotExist)

	// A file that does not parse names itself in the error.
	bad := filepath.Join(t.TempDir(), "networking.allow")
	require.NoError(t, os.WriteFile(bad, []byte("nonsense\n"), 0o600))
	_, err = loadAllowList(bad, false)
	require.ErrorContains(t, err, bad)
	require.ErrorContains(t, err, "line 1")
}
