package codefly_test

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/require"
)

// TestInitEnablesTelemetryExportWhenAnIntakeIsDelivered pins the SDK half of
// the telemetry seam: a process handed OTEL_EXPORTER_OTLP_ENDPOINT by Codefly
// exports without declaring anything, a process handed none stays silent, and
// ShutdownTelemetry is safe either way.
func TestInitEnablesTelemetryExportWhenAnIntakeIsDelivered(t *testing.T) {
	t.Setenv(resources.ModulePrefix, "saas")
	t.Setenv(resources.ServicePrefix, "accounts")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	_, err := codefly.Init(context.Background())
	require.NoError(t, err)
	require.NoError(t, codefly.ShutdownTelemetry(context.Background()), "nothing enabled, nothing to stop")

	// A URL to a port nothing listens on: the exporter is built (gRPC dials
	// lazily), so Init succeeds, and the shutdown flushes an empty batch.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_SERVICE_NAME", "saas/accounts")
	_, err = codefly.Init(context.Background())
	require.NoError(t, err)
	require.NoError(t, codefly.ShutdownTelemetry(context.Background()))
}
