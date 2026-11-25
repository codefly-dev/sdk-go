package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// trackedFiles lists the files git tracks under dir, as slash-separated paths
// relative to dir. Only tracked files are read: an untracked or ignored file
// (a build output, a local environment file) ships to nobody.
func trackedFiles(dir string) ([]string, error) {
	command := exec.Command("git", "-C", dir, "ls-files", "-z")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("git ls-files in %s: %s", dir, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("git ls-files in %s: %w", dir, err)
	}
	var paths []string
	for _, path := range strings.Split(string(output), "\x00") {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths, nil
}
