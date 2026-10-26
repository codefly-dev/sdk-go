package codefly

import "testing"

// IsolateConsumerIdentityForTest gives each boot scenario a fresh process pin.
// This helper exists only in the test binary; production has no reset API.
func IsolateConsumerIdentityForTest(t *testing.T) {
	t.Helper()
	consumerIdentityMu.Lock()
	previous := consumerIdentity
	consumerIdentity = ""
	consumerIdentityMu.Unlock()
	previousModule, previousService, previousContext := module, service, runningCtx
	t.Cleanup(func() {
		consumerIdentityMu.Lock()
		consumerIdentity = previous
		consumerIdentityMu.Unlock()
		module, service, runningCtx = previousModule, previousService, previousContext
	})
}
