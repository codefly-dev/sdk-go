package codefly

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/codefly-dev/core/resources"
)

// A document lookup reports one of these outcomes so a caller can tell an
// absent document from a broken one, and both from a document that exists and
// carries an explicit JSON null.
var (
	// ErrConfigurationDocumentMissing reports that the selected scope carries
	// no document. An empty carrier is absent, not an empty document.
	ErrConfigurationDocumentMissing = errors.New("no document is provisioned in the selected scope")

	// ErrConfigurationDocumentUnreadable reports that the selected scope
	// carries a document this SDK cannot read: a malformed carrier, one whose
	// scope does not match the request, or one declaring a schema this SDK
	// does not implement. The reported reason carries no document content.
	ErrConfigurationDocumentUnreadable = errors.New("document carrier cannot be read")

	// ErrConfigurationDocumentNull reports an explicit JSON null to a typed
	// decoder, which would otherwise leave the destination at its zero value
	// and look like a document that was never provisioned. The raw accessors
	// return the document's null bytes instead.
	ErrConfigurationDocumentNull = errors.New("document is an explicit JSON null")
)

// ConfigurationDocument returns an independent JSON document from the selected
// service's runtime configuration. It preserves nested values and JSON numbers.
func (q *Query) ConfigurationDocument(name string) (json.RawMessage, error) {
	return q.configurationDocument(resources.ServiceUnique(q.module, q.service), name, false)
}

// SecretDocument reads the selected service's secret document namespace.
// Returned bytes contain secrets and must not be logged or rendered into GitOps.
func (q *Query) SecretDocument(name string) (json.RawMessage, error) {
	return q.configurationDocument(resources.ServiceUnique(q.module, q.service), name, true)
}

// WorkspaceConfigurationDocument reads a public workspace document.
func (q *Query) WorkspaceConfigurationDocument(name string) (json.RawMessage, error) {
	return q.configurationDocument(resources.ConfigurationWorkspace, name, false)
}

// WorkspaceSecretDocument reads a secret workspace document.
func (q *Query) WorkspaceSecretDocument(name string) (json.RawMessage, error) {
	return q.configurationDocument(resources.ConfigurationWorkspace, name, true)
}

// DecodeConfigurationDocument decodes the selected service's public document
// into a typed destination, retaining json.Number when the destination is any.
func (q *Query) DecodeConfigurationDocument(name string, destination any) error {
	content, err := q.ConfigurationDocument(name)
	if err != nil {
		return err
	}
	return decodeDocument(name, content, destination)
}

// DecodeSecretDocument decodes a service secret without including its contents
// or decoder details in an error.
func (q *Query) DecodeSecretDocument(name string, destination any) error {
	content, err := q.SecretDocument(name)
	if err != nil {
		return err
	}
	return decodeDocument(name, content, destination)
}

// DecodeWorkspaceConfigurationDocument decodes a public workspace document.
func (q *Query) DecodeWorkspaceConfigurationDocument(name string, destination any) error {
	content, err := q.WorkspaceConfigurationDocument(name)
	if err != nil {
		return err
	}
	return decodeDocument(name, content, destination)
}

// DecodeWorkspaceSecretDocument decodes a secret workspace document without
// disclosing its contents in errors.
func (q *Query) DecodeWorkspaceSecretDocument(name string, destination any) error {
	content, err := q.WorkspaceSecretDocument(name)
	if err != nil {
		return err
	}
	return decodeDocument(name, content, destination)
}

func decodeDocument(name string, content json.RawMessage, destination any) error {
	if string(bytes.TrimSpace(content)) == "null" {
		return fmt.Errorf("configuration document %q: %w", name, ErrConfigurationDocumentNull)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("configuration document %q does not match the requested destination", name)
	}
	return nil
}

func (q *Query) configurationDocument(origin, name string, secret bool) (json.RawMessage, error) {
	if name == "" || (origin != resources.ConfigurationWorkspace && (q.module == "" || q.service == "")) {
		return nil, fmt.Errorf("configuration document requires a name and a complete service identity")
	}
	environment := localConfigurationEnvironmentName()
	key := resources.ConfigurationDocumentKey(origin, name, environment, secret)
	value, found := injectedEnvironmentValue(key)
	if !found || strings.TrimSpace(value) == "" {
		value, found = os.LookupEnv(key)
	}
	if !found || strings.TrimSpace(value) == "" {
		var err error
		value, err = resources.FindValueInEnvironmentVariables(q.ctx, key, codeflyEnvironmentVariables())
		found = err == nil
	}
	if !found || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("configuration document %q: %w", name, ErrConfigurationDocumentMissing)
	}
	content, err := resources.DecodeConfigurationDocument(value, origin, name, environment, secret)
	if err != nil {
		return nil, fmt.Errorf("configuration document %q: %w: %v", name, ErrConfigurationDocumentUnreadable, err)
	}
	return content, nil
}
