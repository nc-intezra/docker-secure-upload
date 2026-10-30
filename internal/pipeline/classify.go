// Package pipeline scans completed uploads, routes each one to its end
// state, publishes passed files to the outbox and writes batch manifests.
package pipeline

import (
	"fmt"
	"strings"

	"github.com/nc-intezra/docker-secure-upload/internal/clamd"
	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

// Decision is where a scanned file goes and why.
type Decision struct {
	State  store.State
	Reason string // shown to admins and recorded in the manifest
}

// Policy holds the settings Classify needs.
type Policy struct {
	MaxScanSize       int64
	Oversize          config.OversizePolicy
	QuarantineEnabled bool
}

// Classify maps a clamd result to an end state. It never treats an
// unexpected or partial result as clean.
func Classify(res clamd.Result, scanErr error, size int64, p Policy) Decision {
	if scanErr != nil {
		return Decision{store.StateHeld, "scan failed: " + scanErr.Error()}
	}
	switch res.Verdict {
	case clamd.VerdictOK:
		if size > p.MaxScanSize {
			// clamd may silently skip data past its limits; never trust OK
			// for a file larger than it can read in full.
			return unscanned(p, fmt.Sprintf("file is %d bytes, larger than the scanner limit of %d bytes", size, p.MaxScanSize))
		}
		return Decision{store.StatePassed, ""}
	case clamd.VerdictFound:
		sig := res.Signature
		switch {
		case strings.HasPrefix(sig, "Heuristics.Limits.Exceeded.MaxFileSize"),
			strings.HasPrefix(sig, "Heuristics.Limits.Exceeded.MaxScanSize"):
			return unscanned(p, "scanner size limit reached ("+sig+")")
		case strings.HasPrefix(sig, "Heuristics.Limits.Exceeded."):
			// Recursion depth, file count or scan time: the shape of an
			// archive bomb. Never pass these automatically.
			return Decision{store.StateHeld, "scanner limit reached (" + sig + ")"}
		}
		if p.QuarantineEnabled {
			return Decision{store.StateQuarantined, "infected: " + sig}
		}
		return Decision{store.StateDeleted, "infected: " + sig}
	case clamd.VerdictError:
		return Decision{store.StateHeld, "scan error: " + res.Message}
	}
	return Decision{store.StateHeld, "unrecognized scan result"}
}

func unscanned(p Policy, reason string) Decision {
	if p.Oversize == config.OversizePass {
		return Decision{store.StateUnscanned, reason}
	}
	// "reject" is enforced when the upload is created; anything that still
	// arrives here is held rather than passed.
	return Decision{store.StateHeld, reason}
}
