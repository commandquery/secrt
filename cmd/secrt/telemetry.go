package main

import (
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

// BuildID is set by the linker at build time with
// -ldflags "-X main.BuildID=abc123"
var BuildID string = "undefined"

// CollectTelemetry collects non-identifying performance data from the client application.
// Telemetry is governed by our privacy policy and must never collect data that could identify
// an individual user.
//
// Telemetry can be disabled with `secrt set telemetry=false`
func CollectTelemetry(command string, exitCode int, startTime time.Time) secrt.Telemetry {
	t := secrt.Telemetry{
		BuildID:   BuildID,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Command:   command,
		ExitCode:  exitCode,
		ElapsedMs: time.Since(startTime).Milliseconds(),
	}

	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err == nil {
		utime := rusage.Utime.Nano() / 1e6 // reduce resolution to avoid fingerprinting
		stime := rusage.Stime.Nano() / 1e6 // reduce resolution to avoid fingerprinting
		t.UtimeMs = &utime
		t.StimeMs = &stime
	}

	return t
}

// SendTelemetry makes a best-effort attempt to send some telemetry but if it fails, it fails.
// Telemetry must not be transmitted if the user has requested that it be disabled.
func SendTelemetry(config *Config, endpoint *Endpoint, command string, exitCode int, startTime time.Time) {
	if !config.Properties.Telemetry {
		return
	}

	if os.Getenv("SECRT_TELEMETRY") == "false" {
		return
	}

	telemetry := CollectTelemetry(command, exitCode, startTime)
	_ = Call(endpoint, &telemetry, jtp.Nil, "POST", "telemetry")
}
