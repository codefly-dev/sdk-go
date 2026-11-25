// Command netguard refuses a hardcoded network address in a repository.
//
// The rule it holds: every host, port, DSN and URL is resolved through the
// Codefly SDK. A literal `localhost:8080`, a `postgres://…` connection string,
// an `http://host:port` URL or a fixed port constant is a finding; port 0 is
// never one.
//
// Usage, from any repository:
//
//	go run github.com/codefly-dev/sdk-go/cmd/netguard@<sha> [flags] [dir]
//
//	-allow <file>   the allow-list, relative to dir (default scripts/networking.allow;
//	                a missing default file is an empty list)
//	-summary        print only the counts
//
// It reads the files git tracks under dir (the working-tree content of each),
// reports `path:line: literal` for every finding the allow-list does not cover,
// and exits 1 when there is one, or when an allow-list entry covers nothing.
// It exits 2 when it could not run: a bad flag, a directory git does not know,
// an allow-list it cannot parse.
//
// What is never a finding, with no entry needed: port 0; the sentinels
// 127.0.0.1:1 and localhost:9; a host under .invalid, .test or .example, or
// example.com, example.org or example.net; an address in 192.0.2.0/24,
// 198.51.100.0/24 or 203.0.113.0/24; a bare scheme with nothing after it
// ("postgres://"); a bare host with no port.
//
// The allow-list is tab-separated, one literal per line:
//
//	# class	path-glob	literal	reason
//	vector	pkg/auth/*_test.go	http://localhost:54321/callback	OAuth loopback redirect under test
//	agent	templates/deployment/**	8080	standards.Port(rest)
//	doc	docs/**	*	prose
//	exclude	deployments/**	*	rendered by codefly
//
// class is one of vector, protocol, agent, bind, doc, external, exclude. `*` as
// the literal is accepted for doc and exclude only. A vector entry covers a
// finding in a test path and nowhere else. An entry that covers nothing fails
// the run, so the list shrinks when the code is cleaned. There is no baseline
// class: a known violation is fixed or it fails.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	exitClean     = 0
	exitViolation = 1
	exitUnusable  = 2

	defaultAllowList = "scripts/networking.allow"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// options is one invocation, parsed.
type options struct {
	dir     string
	allow   string
	summary bool
	// allowNamed is true when -allow was given: a named file must exist, the
	// default one may be absent.
	allowNamed bool
}

func parseArguments(arguments []string) (options, error) {
	parsed := options{dir: ".", allow: defaultAllowList}
	var positional []string
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		name, value, hasValue := strings.Cut(argument, "=")
		switch name {
		case "-allow", "--allow":
			if !hasValue {
				index++
				if index >= len(arguments) {
					return options{}, errors.New("-allow needs a file")
				}
				value = arguments[index]
			}
			if value == "" {
				return options{}, errors.New("-allow needs a file")
			}
			parsed.allow, parsed.allowNamed = value, true
		case "-summary", "--summary":
			if hasValue {
				return options{}, errors.New("-summary takes no value")
			}
			parsed.summary = true
		default:
			if strings.HasPrefix(argument, "-") {
				return options{}, fmt.Errorf("unknown flag %s", argument)
			}
			positional = append(positional, argument)
		}
	}
	switch len(positional) {
	case 0:
	case 1:
		parsed.dir = positional[0]
	default:
		return options{}, fmt.Errorf("one directory at most, got %d", len(positional))
	}
	return parsed, nil
}

// run is the whole command, returning its exit status.
func run(arguments []string, stdout, stderr io.Writer) int {
	parsed, err := parseArguments(arguments)
	if err != nil {
		writef(stderr, "netguard: %v\nusage: netguard [-allow file] [-summary] [dir]\n", err)
		return exitUnusable
	}

	allowPath := parsed.allow
	if !filepath.IsAbs(allowPath) {
		allowPath = filepath.Join(parsed.dir, allowPath)
	}
	list, err := loadAllowList(allowPath, parsed.allowNamed)
	if err != nil {
		writef(stderr, "netguard: %v\n", err)
		return exitUnusable
	}

	tracked, err := trackedFiles(parsed.dir)
	if err != nil {
		writef(stderr, "netguard: %v\n", err)
		return exitUnusable
	}

	// The allow-list names the literals it permits, so it is never scanned.
	allowRelative := ""
	if relative, relErr := filepath.Rel(parsed.dir, allowPath); relErr == nil {
		allowRelative = filepath.ToSlash(relative)
	}

	var violations []finding
	for _, path := range tracked {
		if path == allowRelative || builtinExcluded(path) || list.excludes(path) {
			continue
		}
		content, readable := readText(filepath.Join(parsed.dir, filepath.FromSlash(path)))
		if !readable {
			continue
		}
		for _, found := range scan(path, content) {
			if !list.covers(found) {
				violations = append(violations, found)
			}
		}
	}
	unused := list.unused()

	report(stdout, parsed, violations, unused)
	if len(violations) > 0 || len(unused) > 0 {
		return exitViolation
	}
	return exitClean
}

// readText returns a tracked file's content, and false for what is not text to
// scan: a path that is not a regular file (a symlink, a submodule), a file
// deleted from the working tree, or binary content.
func readText(path string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	sniff := content
	if len(sniff) > 8000 {
		sniff = sniff[:8000]
	}
	if strings.IndexByte(string(sniff), 0) >= 0 {
		return "", false
	}
	return string(content), true
}

func report(stdout io.Writer, parsed options, violations []finding, unused []allowEntry) {
	counts := map[string]int{}
	classes := map[string]bool{}
	for _, violation := range violations {
		counts[violation.kind]++
		classes[violation.class] = true
		if !parsed.summary {
			writef(stdout, "%s:%d: %s\t[%s, %s]\n", violation.path, violation.line, violation.literal, violation.class, violation.kind)
		}
	}
	if !parsed.summary {
		for _, entry := range unused {
			writef(stdout, "%s:%d: allow-list entry covers nothing: %s %s %s\n", parsed.allow, entry.line, entry.class, entry.glob, entry.literal)
		}
		names := make([]string, 0, len(classes))
		for class := range classes {
			names = append(names, class)
		}
		sort.Strings(names)
		for _, class := range names {
			writef(stdout, "fix %s: %s\n", class, cookbook[class])
		}
	}
	writef(stdout, "netguard: %d violations (runtime %d, test %d, doc %d), %d unused allow-list entries\n",
		len(violations), counts[kindRuntime], counts[kindTest], counts[kindDoc], len(unused))
}

// cookbook is the replacement for each class of literal.
var cookbook = map[string]string{
	classHostPort: "resolve the address through the SDK (Go: codefly.For(ctx).Service(s).API(api).ResolveNetworkInstance(); TypeScript: networkInstance({service, api, protocol}); shell: codefly endpoint <module>/<service> --type <api>). A test listener binds 127.0.0.1:0 and reads the port back; a value that must not connect is 127.0.0.1:1 or a .invalid name.",
	classDSN:      "read the connection from the SDK (Go: codefly.For(ctx).Service(s).Secret(\"postgres\", \"read-write-connection\"); Python: codefly.secret(name=..., key=..., service=...)); a test gets it from sdk.WithDependencies, never by splicing a host and port into a DSN.",
	classURL:      "resolve the URL through the SDK (Go: ResolveNetworkInstance(); TypeScript: networkInstance(...); an external base URL: WorkspaceConfiguration(name, key)). A URL that must not connect uses a .invalid, .test or .example host.",
	classPort:     "take the port from the service's own endpoint (the injected PORT, ResolveNetworkInstance().Port) or, in an agent, from the one port source (standards.Port(api)); a template renders it from a variable.",
}

func writef(to io.Writer, format string, arguments ...any) {
	// A report that cannot be written has nowhere to be reported to.
	_, _ = fmt.Fprintf(to, format, arguments...)
}
