package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"batch.created", "upload.created", "upload.passed"} {
		if err := l.Append(Event{ActorType: "user", Actor: "jsmith", Action: a}); err != nil {
			t.Fatal(err)
		}
	}
	// Reopen and continue the chain.
	l2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Append(Event{ActorType: "system", Actor: "scanner", Action: "x"}); err != nil {
		t.Fatal(err)
	}
	n, err := Verify(dir)
	if err != nil || n != 4 {
		t.Fatalf("Verify = %d, %v", n, err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	b, _ := os.ReadFile(files[0])
	tampered := strings.Replace(string(b), `"actor":"jsmith"`, `"actor":"mallory"`, 1)
	if err := os.WriteFile(files[0], []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("tamper not detected: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	deleted := strings.Join(append([]string{lines[0]}, lines[2:]...), "\n") + "\n"
	os.WriteFile(files[0], []byte(deleted), 0o600)
	if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "chain broken") {
		t.Fatalf("deletion not detected: %v", err)
	}
}
