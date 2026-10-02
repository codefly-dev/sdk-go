package codefly

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors a caller distinguishes when it reads an authority-bearing value.
var (
	// ErrAuthorityValueMissing reports that a declared authority-bearing value
	// is not configured. It is a boot error: the process has no authority to
	// run under and must not serve.
	ErrAuthorityValueMissing = errors.New("codefly: authority-bearing value is not configured")

	// ErrAuthorityValueChanged reports that an authority-bearing value resolves
	// differently now than it did when the process read it. The host is the
	// authority for these values, so a value that drifts under a running
	// process is an error and never a reload: the process that read the old
	// value already minted a credential against it.
	ErrAuthorityValueChanged = errors.New("codefly: authority-bearing value changed under a running process")

	// ErrAuthorityValueUnread reports a lookup for a value the process did not
	// declare when it read its authority. Declaring the set up front is what
	// makes "read once" checkable.
	ErrAuthorityValueUnread = errors.New("codefly: authority-bearing value was not read at boot")
)

// AuthorityValueName addresses one workspace value by the name and key the
// workspace accessors take, never by its carrier.
type AuthorityValueName struct {
	Name string
	Key  string
}

func (n AuthorityValueName) String() string {
	return n.Name + "/" + n.Key
}

func (n AuthorityValueName) canonical() AuthorityValueName {
	return AuthorityValueName{
		Name: strings.TrimSpace(n.Name),
		Key:  strings.TrimSpace(n.Key),
	}
}

// Authority is the set of authority-bearing workspace values a process read
// once, at boot: the principal it runs as, the binding it serves, the audience
// it mints against. Nothing in the set can be re-read into a different value,
// because the credential the process already holds is sealed to the values it
// was minted under.
//
// Read it once during startup, before serving, and treat a non-nil error as
// fatal. Hand the resolved strings to whatever mints the process credential,
// and call Recheck before every renewal so a drifted value refuses the renewal
// instead of silently re-sealing to something the host never approved.
type Authority struct {
	readAt time.Time
	values map[AuthorityValueName]string
}

// authorityPins is the process-wide record of what has been pinned. It exists
// so a later WorkspaceValue for a pinned name cannot answer with a value that
// drifted after boot: without it, reading the authority through Authority and
// reading the same name through the ordinary accessor would disagree, and the
// ordinary accessor is the one product code reaches for by habit.
var (
	authorityPinsMu sync.RWMutex
	authorityPins   = map[AuthorityValueName]string{}
)

// ReadAuthority resolves every named value once and freezes the result. A name
// that resolves to nothing fails the whole read: a partially-known authority is
// not an authority, and continuing with the rest would let a process serve
// under an identity it could not fully establish.
//
// Calling it twice with the same name is allowed and must agree — the second
// read is checked against the pin exactly as Recheck would check it.
func ReadAuthority(ctx context.Context, names ...AuthorityValueName) (*Authority, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: no names given", ErrAuthorityValueMissing)
	}
	query := For(ctx)
	values := make(map[AuthorityValueName]string, len(names))
	for _, raw := range names {
		name := raw.canonical()
		if name.Name == "" || name.Key == "" {
			return nil, fmt.Errorf("%w: a name and a key are both required", ErrAuthorityValueMissing)
		}
		if _, duplicate := values[name]; duplicate {
			continue
		}
		value, err := query.workspaceValueLive(name.Name, name.Key)
		if err != nil || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%w: %s", ErrAuthorityValueMissing, name)
		}
		values[name] = value
	}
	// Compare and install together, under one hold of the write lock. Checking
	// the pins here and writing them afterwards was a race with a wrong
	// outcome rather than a torn read: two goroutines reading the same name
	// across a configuration reload both saw no pin, both resolved — to
	// different values — and both succeeded, the second pin overwriting the
	// first. Two live *Authority values then disagreed about the audience the
	// process runs under, and the race detector sees nothing because every
	// access was correctly locked.
	if err := pinAuthorityValues(values); err != nil {
		return nil, err
	}
	return &Authority{readAt: time.Now().UTC(), values: values}, nil
}

// Value answers from the frozen set. It performs no lookup, so it cannot
// observe a change; Recheck is what observes one.
func (a *Authority) Value(name string, key string) (string, error) {
	if a == nil {
		return "", fmt.Errorf("%w: authority was never read", ErrAuthorityValueUnread)
	}
	addressed := AuthorityValueName{Name: name, Key: key}.canonical()
	value, ok := a.values[addressed]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrAuthorityValueUnread, addressed)
	}
	return value, nil
}

// Names returns the declared set, sorted, for a boot log that records what the
// process established its identity from.
func (a *Authority) Names() []AuthorityValueName {
	if a == nil {
		return nil
	}
	names := make([]AuthorityValueName, 0, len(a.values))
	for name := range a.values {
		names = append(names, name)
	}
	sortAuthorityValueNames(names)
	return names
}

// ReadAt reports when the set was frozen.
func (a *Authority) ReadAt() time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.readAt
}

// Recheck re-resolves every value in the set and refuses on the first that
// moved. A value that has disappeared counts as moved: the host withdrawing an
// authority-bearing value is a withdrawal, not an absence to tolerate.
//
// It is deliberately a check and not a reload. Nothing here updates the frozen
// set, because a credential already sealed to the old value cannot be made
// correct by forgetting what it was sealed to.
func (a *Authority) Recheck(ctx context.Context) error {
	if a == nil {
		return fmt.Errorf("%w: authority was never read", ErrAuthorityValueUnread)
	}
	query := For(ctx)
	for _, name := range a.Names() {
		value, err := query.workspaceValueLive(name.Name, name.Key)
		if err != nil || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is no longer configured", ErrAuthorityValueChanged, name)
		}
		if value != a.values[name] {
			return fmt.Errorf("%w: %s", ErrAuthorityValueChanged, name)
		}
	}
	return nil
}

func authorityPin(name AuthorityValueName) (string, bool) {
	authorityPinsMu.RLock()
	defer authorityPinsMu.RUnlock()
	value, ok := authorityPins[name]
	return value, ok
}

// pinAuthorityValues installs the whole proposed set or none of it.
//
// It compares every member against what is already pinned before it writes any
// member, so a set that conflicts in one name leaves the pins exactly as they
// were. A partial install would be the same defect ReadAuthority refuses for a
// partial read: a process running under an authority it could only half
// establish, with the half that moved silently replaced.
//
// Conflicts are reported in a stable order, so two processes racing on the same
// drift name the same value rather than whichever map iteration reached first.
func pinAuthorityValues(values map[AuthorityValueName]string) error {
	names := make([]AuthorityValueName, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sortAuthorityValueNames(names)
	authorityPinsMu.Lock()
	defer authorityPinsMu.Unlock()
	for _, name := range names {
		if pinned, ok := authorityPins[name]; ok && pinned != values[name] {
			return fmt.Errorf("%w: %s", ErrAuthorityValueChanged, name)
		}
	}
	for name, value := range values {
		authorityPins[name] = value
	}
	return nil
}

func sortAuthorityValueNames(names []AuthorityValueName) {
	sort.Slice(names, func(i, j int) bool {
		if names[i].Name != names[j].Name {
			return names[i].Name < names[j].Name
		}
		return names[i].Key < names[j].Key
	})
}
