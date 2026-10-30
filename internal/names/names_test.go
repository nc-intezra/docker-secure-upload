package names

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeUsername(t *testing.T) {
	good := map[string]string{"jsmith": "jsmith", " JSmith ": "jsmith", "a.b-c_d": "a.b-c_d", "x": "x"}
	for in, want := range good {
		got, err := NormalizeUsername(in)
		if err != nil || got != want {
			t.Errorf("NormalizeUsername(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "1abc", "-abc", "a b", "a/b", "a\nb", "ab;rm", strings.Repeat("a", 33), "jsmithé", "<script>"}
	for _, in := range bad {
		if _, err := NormalizeUsername(in); err == nil {
			t.Errorf("NormalizeUsername(%q) accepted", in)
		}
	}
}

func TestBatchID(t *testing.T) {
	id := NewBatchID(time.Date(2026, 10, 30, 14, 15, 2, 0, time.UTC), "jsmith")
	if !strings.HasPrefix(id, "20261030T141502Z-jsmith-") || !ValidBatchID(id) {
		t.Fatalf("bad batch id %q", id)
	}
	for _, bad := range []string{"", "../x", "20261030T141502Z-jsmith-zzzzzz", "20261030T141502Z-JSMITH-a3f9c1"} {
		if ValidBatchID(bad) {
			t.Errorf("ValidBatchID(%q) = true", bad)
		}
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"Site Survey.zip":         "Site_Survey.zip",
		"../../etc/passwd":        "passwd",
		"..\\..\\boot.ini":        "boot.ini",
		".bashrc":                 "bashrc",
		"-rf":                     "rf",
		"résumé final.pdf":        "r_sum_final.pdf",
		"a  ;$(rm -rf /).txt":     "_.txt",
		"a  ;$(rm -rf).txt":       "a_rm_-rf_.txt",
		"CON.txt":                 "_CON.txt",
		"nul":                     "_nul",
		"com1.tar.gz":             "_com1.tar.gz",
		"":                        "file",
		"...":                     "file",
		"/":                       "file",
		"日本語":                     "file",
		"report.":                 "report",
		"name\x00with\x00nul.bin": "name_with_nul.bin",
	}
	for in, want := range cases {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 300) + ".qcow2"
	got := SafeName(long)
	if len(got) != 120 || !strings.HasSuffix(got, ".qcow2") {
		t.Errorf("long name not truncated with extension: %q (%d)", got, len(got))
	}
}

func TestOutboxName(t *testing.T) {
	got := OutboxName("20261030T141502Z-jsmith-a3f9c1", 2, "vm image.qcow2")
	if got != "20261030T141502Z-jsmith-a3f9c1_002_vm_image.qcow2" {
		t.Fatal(got)
	}
}

func TestCleanOriginal(t *testing.T) {
	if _, err := CleanOriginal("ok name.txt"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "a\nb", "a\x1bb", "\xff\xfe", strings.Repeat("a", 1025), "a b"} {
		if _, err := CleanOriginal(bad); err == nil {
			t.Errorf("CleanOriginal(%q) accepted", bad)
		}
	}
}
