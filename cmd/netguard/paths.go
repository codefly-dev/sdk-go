package main

import (
	"path/filepath"
	"strings"
)

// The three kinds of place a finding is in. They do not change whether it is a
// finding; they say what it costs: a runtime literal ships, a test literal
// dials from a test, a doc literal is read by a person.
const (
	kindRuntime = "runtime"
	kindTest    = "test"
	kindDoc     = "doc"
)

// excludedSegments are directories whose content this repository did not
// write: installed dependencies, generated bindings and built output.
var excludedSegments = map[string]bool{
	"node_modules": true, "vendor": true, "dist": true, "gen": true, "generated": true,
}

// excludedNames and excludedSuffixes are lockfiles, protobuf output, built
// JavaScript, snapshots and the formats that carry no address a process dials.
var excludedNames = map[string]bool{
	"package-lock.json": true, "pnpm-lock.yaml": true, "go.sum": true, "uv.lock": true,
}

var excludedSuffixes = []string{
	".lock", ".pb.go", ".pb.gw.go", "_pb.ts", "_pb.js", ".swagger.json", ".min.js", ".map", ".svg", ".snap", ".ipynb",
}

// builtinExcluded reports a path no repository has to list as excluded.
func builtinExcluded(path string) bool {
	segments := strings.Split(path, "/")
	name := segments[len(segments)-1]
	for _, segment := range segments[:len(segments)-1] {
		if excludedSegments[segment] {
			return true
		}
	}
	if excludedNames[name] {
		return true
	}
	for _, suffix := range excludedSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	// Python protobuf output: x_pb2.py, x_pb2_grpc.py, x_pb2.pyi.
	if strings.Contains(name, "_pb2") && (strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".pyi")) {
		return true
	}
	// OpenAPI documents under an openapi/ directory.
	if len(segments) >= 2 && segments[len(segments)-2] == "openapi" && strings.HasSuffix(name, ".json") {
		return true
	}
	return false
}

var docSegments = map[string]bool{"docs": true, "doc": true}

var docSuffixes = []string{".md", ".mdx", ".rst", ".adoc"}

var testSegments = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "__tests": true, "testdata": true, "e2e": true,
	"fixtures": true, "testsupport": true, "testutil": true, "qualification": true, ".github": true,
}

var testSuffixes = []string{
	"_test.go", "_test.py", "_test.rs", ".test.sh", ".tftest.hcl",
	".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".test.mjs", ".test.cjs",
	".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx", ".spec.mjs", ".spec.cjs",
}

// kindOf places a path: a test (by directory or by file name, CI included),
// prose, or everything else, which ships.
func kindOf(path string) string {
	segments := strings.Split(path, "/")
	name := segments[len(segments)-1]
	for _, segment := range segments[:len(segments)-1] {
		if testSegments[segment] {
			return kindTest
		}
	}
	for _, suffix := range testSuffixes {
		if strings.HasSuffix(name, suffix) {
			return kindTest
		}
	}
	// A script named for the test it is: test_admin.py, test-source-read.sh,
	// check-boundaries-test.sh.
	stem, _, _ := strings.Cut(name, ".")
	if name == "conftest.py" || strings.HasPrefix(stem, "test_") || strings.HasPrefix(stem, "test-") ||
		strings.HasSuffix(stem, "_test") || strings.HasSuffix(stem, "-test") {
		return kindTest
	}
	for _, segment := range segments[:len(segments)-1] {
		if docSegments[segment] {
			return kindDoc
		}
	}
	for _, suffix := range docSuffixes {
		if strings.HasSuffix(name, suffix) {
			return kindDoc
		}
	}
	return kindRuntime
}

// globMatch matches a slash-separated path against a glob in which `**` is any
// number of whole segments (none included) and `*` and `?` stay inside one.
func globMatch(glob, path string) bool {
	return matchSegments(strings.Split(glob, "/"), strings.Split(path, "/"))
}

func matchSegments(glob, path []string) bool {
	if len(glob) == 0 {
		return len(path) == 0
	}
	if glob[0] == "**" {
		for skip := 0; skip <= len(path); skip++ {
			if matchSegments(glob[1:], path[skip:]) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	matched, err := filepath.Match(glob[0], path[0])
	if err != nil || !matched {
		return false
	}
	return matchSegments(glob[1:], path[1:])
}

// validGlob reports whether every segment of a glob is a pattern filepath.Match
// accepts, so a malformed entry is refused when read instead of never matching.
func validGlob(glob string) bool {
	if glob == "" {
		return false
	}
	for _, segment := range strings.Split(glob, "/") {
		if segment == "**" {
			continue
		}
		if _, err := filepath.Match(segment, ""); err != nil {
			return false
		}
	}
	return true
}
