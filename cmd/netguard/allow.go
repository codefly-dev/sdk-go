package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// The classes an allow-list entry may carry. `exclude` removes whole paths
// from the scan; the others say why a literal is allowed to stay.
var allowClasses = map[string]bool{
	"vector": true, "protocol": true, "agent": true, "bind": true, "doc": true, "external": true, "exclude": true,
}

const (
	classExclude = "exclude"
	classVector  = "vector"
	classDoc     = "doc"
	anyLiteral   = "*"
)

// allowEntry is one line of the allow-list.
type allowEntry struct {
	line    int
	class   string
	glob    string
	literal string
	reason  string
	used    bool
}

// allowList is a repository's reviewed exceptions.
type allowList struct {
	entries []*allowEntry
}

// loadAllowList reads the allow-list at path. A missing file is an empty list
// unless the caller named it, in which case it is an error: a guard pointed at
// a list that is not there would otherwise pass by allowing nothing it meant
// to, or fail on everything with no explanation.
func loadAllowList(path string, mustExist bool) (*allowList, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mustExist {
			return &allowList{}, nil
		}
		return nil, fmt.Errorf("read allow-list: %w", err)
	}
	list, err := parseAllowList(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return list, nil
}

func parseAllowList(content string) (*allowList, error) {
	list := &allowList{}
	seen := map[string]int{}
	for index, line := range strings.Split(content, "\n") {
		number := index + 1
		line = strings.TrimSuffix(line, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var fields []string
		for _, field := range strings.Split(line, "\t") {
			if field = strings.TrimSpace(field); field != "" {
				fields = append(fields, field)
			}
		}
		if len(fields) != 4 {
			return nil, fmt.Errorf("line %d: want four tab-separated fields (class, path glob, literal, reason), got %d", number, len(fields))
		}
		entry := &allowEntry{line: number, class: fields[0], glob: fields[1], literal: fields[2], reason: fields[3]}
		if !allowClasses[entry.class] {
			return nil, fmt.Errorf("line %d: unknown class %q (vector, protocol, agent, bind, doc, external or exclude)", number, entry.class)
		}
		if !validGlob(entry.glob) {
			return nil, fmt.Errorf("line %d: malformed path glob %q", number, entry.glob)
		}
		switch {
		case entry.class == classExclude && entry.literal != anyLiteral:
			return nil, fmt.Errorf("line %d: an exclude entry removes whole paths, so its literal is *, not %q", number, entry.literal)
		case entry.literal == anyLiteral && entry.class != classExclude && entry.class != classDoc:
			return nil, fmt.Errorf("line %d: * as the literal is accepted for doc and exclude only, not for %s", number, entry.class)
		}
		key := entry.class + "\t" + entry.glob + "\t" + entry.literal
		if first, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("line %d: repeats line %d", number, first)
		}
		seen[key] = number
		list.entries = append(list.entries, entry)
	}
	return list, nil
}

// excludes reports a path an exclude entry removes from the scan.
func (l *allowList) excludes(path string) bool {
	excluded := false
	for _, entry := range l.entries {
		if entry.class == classExclude && globMatch(entry.glob, path) {
			entry.used, excluded = true, true
		}
	}
	return excluded
}

// covers reports a finding an entry allows, and marks every entry that does.
func (l *allowList) covers(found finding) bool {
	covered := false
	for _, entry := range l.entries {
		if entry.class == classExclude {
			continue
		}
		// A vector is a value under test, so it exists in a test and nowhere
		// else: the same literal in shipped code is not covered by it.
		if entry.class == classVector && found.kind != kindTest {
			continue
		}
		if entry.literal != anyLiteral && entry.literal != found.literal {
			continue
		}
		if globMatch(entry.glob, found.path) {
			entry.used, covered = true, true
		}
	}
	return covered
}

// unused returns the entries that covered nothing in this run.
func (l *allowList) unused() []allowEntry {
	var unused []allowEntry
	for _, entry := range l.entries {
		if !entry.used {
			unused = append(unused, *entry)
		}
	}
	return unused
}
