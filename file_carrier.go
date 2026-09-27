package codefly

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/codefly-dev/core/resources"
)

// A configuration value too large for a process environment is delivered as
// a file: the environment carries its path under resources.FileCarrierKey,
// and the value's own key is absent. The SDK reads through it, so every
// accessor returns the value whichever carrier delivered it. See core's
// docs/runnable-binding-delivery.md.
//
// A carrier is fixed at process start, like an environment value: the file
// is read once and kept, so a volume the platform later refreshes does not
// change what a running process reads.

var (
	fileCarrierMu     sync.Mutex
	fileCarrierValues = map[string]string{}
)

// processValue is key's value as the process received it: inline in its
// environment, or in the file its carrier names. An inline value and a
// carrier for the same key are two sources for one fact and are refused, and
// a carrier that cannot be read is an error, never an absent value: an
// unreadable credential must not read as an unset one.
func processValue(key string) (string, bool, error) {
	value, inline := os.LookupEnv(key)
	path, carried := os.LookupEnv(resources.FileCarrierKey(key))
	if !carried || path == "" {
		return value, inline && value != "", nil
	}
	if inline && value != "" {
		return "", false, fmt.Errorf("%w: %s is delivered both inline and by file", resources.ErrFileCarrier, key)
	}
	content, err := readFileCarrier(key, path)
	if err != nil {
		return "", false, err
	}
	return content, content != "", nil
}

// readFileCarrier reads key's file once and keeps it.
func readFileCarrier(key, path string) (string, error) {
	fileCarrierMu.Lock()
	defer fileCarrierMu.Unlock()
	cacheKey := key + "\x00" + path
	if content, ok := fileCarrierValues[cacheKey]; ok {
		return content, nil
	}
	content, err := resources.ReadFileCarrier(key, path)
	if err != nil {
		return "", err
	}
	fileCarrierValues[cacheKey] = content
	return content, nil
}

// fileCarriedValues resolves every file carrier of environ ("KEY=VALUE"
// strings, as os.Environ returns them) into the value it carries, under the
// same rules as a direct lookup and through the same once-read cache.
func fileCarriedValues(environ []string) (map[string]string, error) {
	inline := map[string]bool{}
	carriers := map[string]string{}
	for _, entry := range environ {
		key, value, found := strings.Cut(entry, "=")
		if !found || value == "" {
			continue
		}
		if resources.IsFileCarrierKey(key) {
			carriers[resources.CarriedKey(key)] = value
			continue
		}
		inline[key] = true
	}
	resolved := make(map[string]string, len(carriers))
	for key, path := range carriers {
		if inline[key] {
			return nil, fmt.Errorf("%w: %s is delivered both inline and by file", resources.ErrFileCarrier, key)
		}
		content, err := readFileCarrier(key, path)
		if err != nil {
			return nil, err
		}
		resolved[key] = content
	}
	return resolved, nil
}
