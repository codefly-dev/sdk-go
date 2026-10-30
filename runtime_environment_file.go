package codefly

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/codefly-dev/core/resources"
)

const (
	maxRuntimeEnvironmentFileBytes = 4 * 1024 * 1024
	maxRuntimeEnvironmentLineBytes = 1024 * 1024
)

// LoadRuntimeEnvironmentFile imports one Codefly-generated --output-env
// artifact into the process environment. It must be called before Init.
//
// The file is data, not a shell script: values are preserved byte-for-byte
// after the first '=' and are never evaluated. Only CODEFLY__ carriers are
// accepted. Because the artifact can contain service secrets, group or
// world-accessible files are rejected.
func LoadRuntimeEnvironmentFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("Codefly runtime environment file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat Codefly runtime environment file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Codefly runtime environment file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("Codefly runtime environment file must be a regular file")
	}
	if info.Size() > maxRuntimeEnvironmentFileBytes {
		return fmt.Errorf(
			"Codefly runtime environment file exceeds %d bytes",
			maxRuntimeEnvironmentFileBytes,
		)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("Codefly runtime environment file must not be accessible by group or world")
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Codefly runtime environment file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	limited := io.LimitReader(file, maxRuntimeEnvironmentFileBytes+1)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64*1024), maxRuntimeEnvironmentLineBytes)
	values := make(map[string]string)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found || !validRuntimeEnvironmentName(name) {
			return fmt.Errorf("invalid Codefly runtime environment entry at line %d", lineNumber)
		}
		values[name] = value
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Codefly runtime environment file: %w", err)
	}
	if len(values) == 0 {
		return errors.New("Codefly runtime environment file contains no carriers")
	}

	// Mutate only after the complete artifact has passed validation.
	for name, value := range values {
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("set Codefly runtime environment carrier %q: %w", name, err)
		}
	}
	return nil
}

func validRuntimeEnvironmentName(name string) bool {
	if !strings.HasPrefix(name, "CODEFLY__") || len(name) == len("CODEFLY__") {
		return false
	}
	if isConfigurationDocumentCarrier(name) {
		return true
	}
	for _, character := range name {
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '_':
		default:
			return false
		}
	}
	return true
}

// isConfigurationDocumentCarrier reports a structured configuration document's
// carrier exactly as core mints it (resources.ConfigurationDocumentKey): one of
// the two document prefixes and a lowercase hex SHA-256, nothing else.
//
// It is the one name outside [A-Z0-9_] an artifact carries. The digest is
// lowercase because core spells it so, and this SDK finds the document by
// calling that same function and looking the result up exactly
// (configurationDocument), as does every consumer built on an earlier core.
// So the grammar admits the name core mints rather than the name changing
// under its readers, and only that shape: a lowercase letter anywhere else is
// still refused.
func isConfigurationDocumentCarrier(name string) bool {
	for _, prefix := range []string{resources.ConfigurationDocumentPrefix, resources.SecretConfigurationDocumentPrefix} {
		digest, found := strings.CutPrefix(name, prefix)
		if !found {
			continue
		}
		if len(digest) != hex.EncodedLen(sha256.Size) {
			return false
		}
		for _, character := range digest {
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
		return true
	}
	return false
}
