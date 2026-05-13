//go:build !windows

package sensor

import (
	"context"
)

// startPlatformSensors on non-Windows platforms is a no-op stub.
// The agent binary cross-compiled for Windows will use sensor_windows.go instead.
func (s *Sensor) startPlatformSensors(_ context.Context) {
	s.logger.Info("Non-Windows platform: ETW sensor subsystems not active. Heartbeat and signal-forward still operational.")
}
