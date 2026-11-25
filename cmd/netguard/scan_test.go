package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// literalsOf scans one line as a shipped Go file and returns `class literal`
// for each finding.
func literalsOf(line string) []string {
	var found []string
	for _, f := range scan("pkg/server.go", line) {
		found = append(found, f.class+" "+f.literal)
	}
	return found
}

func TestScanFindsEachClassOfLiteral(t *testing.T) {
	for name, tc := range map[string]struct {
		line string
		want []string
	}{
		"loopback host and port":           {`conn, err := net.Dial("tcp", "localhost:8080")`, []string{"hostport localhost:8080"}},
		"wildcard bind":                    {`ENV LISTEN=0.0.0.0:8092`, []string{"hostport 0.0.0.0:8092"}},
		"ipv6 loopback":                    {`addr := "[::1]:9090"`, []string{"hostport [::1]:9090"}},
		"docker host":                      {`url = host.docker.internal:5432`, []string{"hostport host.docker.internal:5432"}},
		"a url with a port":                {`base := "http://localhost:2532"`, []string{"url http://localhost:2532"}},
		"a url of a named service":         {`TRACES_URL: http://traces:8080/v1`, []string{"url http://traces:8080"}},
		"a full dsn is one finding":        {`dsn := "postgres://codefly:codefly@localhost:5432/receipts?sslmode=disable"`, []string{"dsn postgres://codefly:codefly@localhost:5432/receipts?sslmode=disable"}},
		"a dsn with a spliced host":        {`dsn := "postgres://postgres:robin@" + address + "/postgres"`, []string{"dsn postgres://postgres:robin@"}},
		"a dsn built by a format":          {`return fmt.Sprintf("postgres://%s@%s:%d/postgres?sslmode=disable", user, host, port)`, []string{"dsn postgres://%s@%s:%d/postgres?sslmode=disable"}},
		"a dsn with no port":               {`db, err := sql.Open("pgx", "postgres://localhost/never-dialled")`, []string{"dsn postgres://localhost/never-dialled"}},
		"redis and clickhouse":             {`a, b := "rediss://cache:6380/0", "clickhouse://evidence.tracing.svc:9000/evidence"`, []string{"dsn rediss://cache:6380/0", "dsn clickhouse://evidence.tracing.svc:9000/evidence"}},
		"a yaml port":                      {`      port: 8080`, []string{"port 8080"}},
		"a container port":                 {`            - containerPort: 3000`, []string{"port 3000"}},
		"an environment port":              {`ENV PORT=3000`, []string{"port 3000"}},
		"a go constant":                    {`const defaultPort = 9090`, []string{"port 9090"}},
		"a go short declaration":           {`	port := 10000`, []string{"port 10000"}},
		"a json port":                      {`{"path": "/readyz", "port": 8081}`, []string{"port 8081"}},
		"a snake-case name":                {`http_port = 4317`, []string{"port 4317"}},
		"a struct field":                   {`config := localProbe{Port: 8080, Timeout: 1}`, []string{"port 8080"}},
		"a port flag":                      {`uvicorn main:app --port 8080`, []string{"port 8080"}},
		"a port flag with equals":          {`next dev --port=3025`, []string{"port 3025"}},
		"a port flag in an exec array":     {`CMD ["uvicorn", "app", "--host", "0.0.0.0", "--port", "8080"]`, []string{"port 8080"}},
		"a published container port":       {`docker run -d --name minio -p 9000:9000 minio`, []string{"port 9000:9000"}},
		"an EXPOSE":                        {`EXPOSE 8080`, []string{"port 8080"}},
		"an EXPOSE of two ports":           {`EXPOSE 8080 9090/tcp`, []string{"port 8080", "port 9090"}},
		"a listen call":                    {`http.ListenAndServe(":3333", r)`, []string{"port :3333"}},
		"a listen call on a low port":      {`net.Listen("tcp", ":80")`, []string{"port :80"}},
		"a bare listen address":            {`addr := ":8443"`, []string{"port :8443"}},
		"the same literal twice is one":    {`a, b := "localhost:8080", "localhost:8080"`, []string{"hostport localhost:8080"}},
		"two literals on one line are two": {`a, b := "localhost:8080", "localhost:8081"`, []string{"hostport localhost:8080", "hostport localhost:8081"}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, literalsOf(tc.line))
		})
	}
}

func TestScanLeavesTheLegitimateFormsAlone(t *testing.T) {
	for name, line := range map[string]string{
		"port 0 on loopback":             `listener, err := net.Listen("tcp", "127.0.0.1:0")`,
		"port 0 on localhost":            `addr := "localhost:0"`,
		"port 0 in a url":                `base := "http://127.0.0.1:0"`,
		"port 0 as a constant":           `port: 0`,
		"port 0 as a flag":               `uvicorn app --port 0`,
		"port 0 published":               `docker run -p 0:5432 postgres`,
		"port 0 in a dsn":                `dsn := "postgres://u@127.0.0.1:0/db"`,
		"the loopback sentinel":          `endpoint := "http://127.0.0.1:1"`,
		"the loopback sentinel, bare":    `endpoint := "127.0.0.1:1"`,
		"the discard sentinel":           `endpoint := "localhost:9"`,
		"a sentinel in a dsn":            `dsn := "postgres://u@127.0.0.1:1/db"`,
		"a .invalid host":                `base_url="http://service.invalid:8080"`,
		"a .test host":                   `origin := "https://app.test:8443"`,
		"a .example host":                `origin := "http://api.example:9000"`,
		"example.com":                    `origin := "https://www.example.com:8443/callback"`,
		"a documentation address":        `peer := "http://192.0.2.10:8080"`,
		"a second documentation range":   `peer := "http://198.51.100.7:8080"`,
		"a third documentation range":    `peer := "http://203.0.113.255:443"`,
		"a reserved host in a dsn":       `dsn := "postgres://reader@db.invalid:5432/records"`,
		"a bare scheme":                  `if strings.HasPrefix(dsn, "postgres://") {`,
		"a bare scheme in prose":         `connection strings start with postgres://.`,
		"a bare scheme in a call":        `strings.TrimPrefix(dsn, "redis://")`,
		"a bare loopback host":           `host := "127.0.0.1"`,
		"a bare localhost":               `if host == "localhost" {`,
		"a url with no port":             `issuer := "https://accounts.google.com/o/oauth2"`,
		"a port read from a variable":    `addr := fmt.Sprintf("localhost:%d", port)`,
		"a templated port":               `port: {{ .Deployment.Parameters.HTTPPort }}`,
		"a shell port variable":          `export DSN_HOST=127.0.0.1:$PORT`,
		"a word that ends in port":       `report: 500`,
		"transport is not a port":        `transport = 100`,
		"support is not a port":          `SUPPORT=1000`,
		"a portfolio is not a port":      `portfolio: 2500`,
		"a comparison is not a constant": `if port == 8080 {`,
		"a time is not a listen address": `stamp := hour + ":30"`,
		"a decimal is not a port":        `export: 1.5`,
		"a version is not a port":        `port_version = 1.25.3`,
		"another host ending the same":   `peer := "my.localhost:8080x"[:0]`,
		"a number too large for a port":  `addr := "localhost:99999"`,
		"a ratio after -p":               `tool -p 100000:1`,
		"an EXPOSE of a variable":        `EXPOSE {{ .HTTPPort }}`,
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, literalsOf(line))
		})
	}
}

// A more specific class owns its span: the parts of a DSN or a URL are not
// reported again as a host:port, and a legitimate literal's parts are not
// reported at all.
func TestScanReportsTheMostSpecificClassOnce(t *testing.T) {
	require.Equal(t, []string{"dsn postgres://u:p@127.0.0.1:5432/db"},
		literalsOf(`x := "postgres://u:p@127.0.0.1:5432/db"`))
	require.Equal(t, []string{"url http://localhost:3000"},
		literalsOf(`origin := "http://localhost:3000/path"`))
	// The reserved host makes the whole DSN legitimate, port included.
	require.Empty(t, literalsOf(`x := "postgres://u@db.test:5432/db"`))
	// A legitimate DSN beside a real literal: only the real one is reported.
	require.Equal(t, []string{"hostport localhost:5432"},
		literalsOf(`a, b := "postgres://u@db.test:5432/db", "localhost:5432"`))
}

func TestScanRecordsThePlaceOfAFinding(t *testing.T) {
	content := "package x\n\nconst a = \"localhost:8080\"\r\n// nothing\nconst b = \"http://localhost:9090\"\n"
	found := scan("pkg/x_test.go", content)
	require.Len(t, found, 2)
	require.Equal(t, finding{path: "pkg/x_test.go", line: 3, class: classHostPort, literal: "localhost:8080", kind: kindTest}, found[0])
	require.Equal(t, finding{path: "pkg/x_test.go", line: 5, class: classURL, literal: "http://localhost:9090", kind: kindTest}, found[1])
}

func TestKindOfPlacesAPath(t *testing.T) {
	for path, want := range map[string]string{
		"pkg/server.go":                          kindRuntime,
		"templates/builder/Dockerfile.tmpl":      kindRuntime,
		"configurations/local/identity.env":      kindRuntime,
		"scripts/run.sh":                         kindRuntime,
		"pkg/server_test.go":                     kindTest,
		"code/tests/admin/helpers.py":            kindTest,
		"code/test_admin.py":                     kindTest,
		"code/conftest.py":                       kindTest,
		"src/lib/__tests__/proxy.ts":             kindTest,
		"src/proxy.test.ts":                      kindTest,
		"src/proxy.spec.tsx":                     kindTest,
		"pkg/testdata/golden.yaml":               kindTest,
		"tests/e2e/global-setup.ts":              kindTest,
		".github/workflows/ci.yml":               kindTest,
		"qualification/hosted/storage.py":        kindTest,
		"modules/gcp/tests/ops_login.tftest.hcl": kindTest,
		"scripts/lib/stores.test.sh":             kindTest,
		"scripts/ci/test-source-read.sh":         kindTest,
		"scripts/check-boundaries-test.sh":       kindTest,
		"README.md":                              kindDoc,
		"docs/running.txt":                       kindDoc,
		"guide/intro.mdx":                        kindDoc,
		// A test directory wins over prose inside it.
		"pkg/testdata/repos/chi/README.md": kindTest,
		// A name that only contains "test" is not a test.
		"pkg/attestation.go": kindRuntime,
		"contest/main.go":    kindRuntime,
	} {
		require.Equal(t, want, kindOf(path), path)
	}
}

func TestBuiltinExcludedPaths(t *testing.T) {
	for _, path := range []string{
		"node_modules/x/index.js", "web/node_modules/x/index.js", "vendor/github.com/x/y.go",
		"dist/index.js", "code/dist/index.js", "gen/api.go", "pkg/generated/api.go",
		"go.sum", "code/package-lock.json", "pnpm-lock.yaml", "uv.lock", "Cargo.lock",
		"api/v1/service.pb.go", "api/v1/service.pb.gw.go", "api/service_pb2.py", "api/service_pb2_grpc.py",
		"api/service_pb.ts", "api/service.swagger.json", "base/openapi/api.json",
		"static/app.min.js", "static/app.js.map", "logo.svg", "src/__snapshots__/x.snap", "notebook.ipynb",
	} {
		require.True(t, builtinExcluded(path), path)
	}
	for _, path := range []string{
		"main.go", "generated.go", "distribution/main.go", "vendors/list.go", "openapi.json",
		"api/service.proto", "pkg/lock.go", "docs/gen.md",
	} {
		require.False(t, builtinExcluded(path), path)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		glob, path string
		want       bool
	}{
		{"gitops.go", "gitops.go", true},
		{"gitops.go", "pkg/gitops.go", false},
		{"**/grpc_gen.go", "grpc_gen.go", true},
		{"**/grpc_gen.go", "base/code/pkg/adapters/grpc_gen.go", true},
		{"docs/**", "docs/a.md", true},
		{"docs/**", "docs/a/b/c.md", true},
		{"docs/**", "docs", true},
		{"docs/**", "mydocs/a.md", false},
		{"pkg/auth/*_test.go", "pkg/auth/oauth_test.go", true},
		{"pkg/auth/*_test.go", "pkg/auth/pg/session_test.go", false},
		{"pkg/**/*_test.go", "pkg/auth/pg/session_test.go", true},
		{"pkg/**/*_test.go", "pkg/session_test.go", true},
		{"templates/deployment/**", "templates/deployment/kustomize/base/service.yaml.tmpl", true},
		{"**", "anything/at/all", true},
		{"*.md", "README.md", true},
		{"*.md", "docs/README.md", false},
		{"a/?.go", "a/b.go", true},
		{"a/?.go", "a/bc.go", false},
		{"[", "[", false},
	} {
		require.Equal(t, tc.want, globMatch(tc.glob, tc.path), fmt.Sprintf("%s ~ %s", tc.glob, tc.path))
	}
	require.True(t, validGlob("pkg/**/*_test.go"))
	require.False(t, validGlob("pkg/[/x"))
	require.False(t, validGlob(""))
}
