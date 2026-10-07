package codefly

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/codefly-dev/core/resources"
)

var (
	consumerIdentityMu sync.RWMutex
	consumerIdentity   string
)

// Init alone establishes the consumer. A later Init checks the original pin;
// it cannot rebind the process to another module.
func pinConsumerIdentity(identity string) error {
	consumerIdentityMu.Lock()
	defer consumerIdentityMu.Unlock()
	if consumerIdentity != "" && consumerIdentity != identity {
		return fmt.Errorf("%w: consumer module differs from Init", ErrAuthorityValueChanged)
	}
	if identity == "" {
		return resources.ErrConsumerNotIdentified
	}
	consumerIdentity = identity
	return nil
}

func pinnedConsumerIdentity() string {
	consumerIdentityMu.RLock()
	defer consumerIdentityMu.RUnlock()
	return consumerIdentity
}

// Check on every resolution, including queries constructed before a drift.
// A snapshot reload cannot hide a change in the runtime's identity carrier.
func checkConsumerIdentity(identity string) error {
	if identity == "" {
		return resources.ErrConsumerNotIdentified
	}
	if strings.TrimSpace(os.Getenv(resources.ModulePrefix)) != identity {
		return fmt.Errorf("%w: consumer module differs from Init", ErrAuthorityValueChanged)
	}
	return nil
}
