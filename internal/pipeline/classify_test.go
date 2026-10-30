package pipeline

import (
	"errors"
	"testing"

	"github.com/nc-intezra/docker-secure-upload/internal/clamd"
	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

func TestClassify(t *testing.T) {
	const limit = 4000 << 20
	on := Policy{MaxScanSize: limit, Oversize: config.OversizePass, QuarantineEnabled: true}
	off := on
	off.QuarantineEnabled = false
	hold := on
	hold.Oversize = config.OversizeHold

	found := func(sig string) clamd.Result { return clamd.Result{Verdict: clamd.VerdictFound, Signature: sig} }
	ok := clamd.Result{Verdict: clamd.VerdictOK}

	cases := []struct {
		name string
		res  clamd.Result
		err  error
		size int64
		p    Policy
		want store.State
	}{
		{"clean", ok, nil, 1000, on, store.StatePassed},
		{"ok but larger than limit", ok, nil, limit + 1, on, store.StateUnscanned},
		{"ok but larger than limit, hold policy", ok, nil, limit + 1, hold, store.StateHeld},
		{"max file size heuristic", found("Heuristics.Limits.Exceeded.MaxFileSize"), nil, 40 << 30, on, store.StateUnscanned},
		{"max scan size heuristic", found("Heuristics.Limits.Exceeded.MaxScanSize"), nil, 40 << 30, on, store.StateUnscanned},
		{"recursion limit is held", found("Heuristics.Limits.Exceeded.MaxRecursion"), nil, 1000, on, store.StateHeld},
		{"file count limit is held", found("Heuristics.Limits.Exceeded.MaxFiles"), nil, 1000, on, store.StateHeld},
		{"scan time limit is held", found("Heuristics.Limits.Exceeded.MaxScanTime"), nil, 1000, on, store.StateHeld},
		{"infected, quarantine on", found("Eicar-Test-Signature"), nil, 68, on, store.StateQuarantined},
		{"infected, quarantine off", found("Eicar-Test-Signature"), nil, 68, off, store.StateDeleted},
		{"encrypted treated as infected", found("Heuristics.Encrypted.Zip"), nil, 1000, on, store.StateQuarantined},
		{"scan error", clamd.Result{Verdict: clamd.VerdictError, Message: "Can't open file"}, nil, 1, on, store.StateHeld},
		{"scan error with quarantine off is still held", clamd.Result{Verdict: clamd.VerdictError}, nil, 1, off, store.StateHeld},
		{"transport failure", clamd.Result{}, errors.New("timeout"), 1, on, store.StateHeld},
		{"empty result", clamd.Result{}, nil, 1, on, store.StateHeld},
	}
	for _, c := range cases {
		if got := Classify(c.res, c.err, c.size, c.p); got.State != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, got.State, got.Reason, c.want)
		}
	}
}
