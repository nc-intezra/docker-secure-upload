package clamd

import (
	"testing"
	"time"
)

func TestParseScanReply(t *testing.T) {
	p := "/data/incoming/abc"
	cases := []struct {
		reply string
		want  Result
		err   bool
	}{
		{p + ": OK", Result{Verdict: VerdictOK}, false},
		{p + ": Eicar-Test-Signature FOUND", Result{Verdict: VerdictFound, Signature: "Eicar-Test-Signature"}, false},
		{p + ": Heuristics.Limits.Exceeded.MaxFileSize FOUND", Result{Verdict: VerdictFound, Signature: "Heuristics.Limits.Exceeded.MaxFileSize"}, false},
		{p + ": lstat() failed: No such file or directory. ERROR", Result{Verdict: VerdictError, Message: "lstat() failed: No such file or directory."}, false},
		{"Access denied. ERROR", Result{Verdict: VerdictError, Message: "Access denied."}, false},
		{"/other: OK", Result{}, true},
		{p + ": maybe", Result{}, true},
		{p + ":  FOUND", Result{}, true},
		{"", Result{}, true},
	}
	for _, c := range cases {
		got, err := ParseScanReply(p, c.reply)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("ParseScanReply(%q) = %+v, %v", c.reply, got, err)
		}
	}
}

func TestParseVersion(t *testing.T) {
	v := ParseVersion("ClamAV 1.4.1/27800/Thu Oct 29 08:24:02 2026")
	if v.Engine != "ClamAV 1.4.1" || v.DBVersion != 27800 || !v.DBTime.Equal(time.Date(2026, 10, 29, 8, 24, 2, 0, time.UTC)) {
		t.Fatalf("%+v", v)
	}
	if v := ParseVersion("ClamAV 1.4.1"); v.DBVersion != 0 || !v.DBTime.IsZero() {
		t.Fatalf("%+v", v)
	}
}
