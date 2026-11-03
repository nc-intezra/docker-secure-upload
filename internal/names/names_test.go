package names

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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
		// Kept exactly as written.
		"Site Survey.zip":             "Site Survey.zip",
		"résumé final (v2).pdf":       "résumé final (v2).pdf",
		"日本語の資料.docx":                 "日本語の資料.docx",
		"-rf":                         "-rf",
		"a  ;$(rm -rf).txt":           "a  ;$(rm -rf).txt",
		"report.tar.gz":               "report.tar.gz",
		"budget [final] & notes.xlsx": "budget [final] & notes.xlsx",
		// Directory parts dropped, whichever separator.
		"../../etc/passwd":    "passwd",
		"..\\..\\boot.ini":    "boot.ini",
		"C:\\Users\\x\\a.txt": "a.txt",
		// Characters illegal on Linux or Windows replaced.
		"what?.txt":               "what_.txt",
		"a<b>c:d\"e|f*g.txt":      "a_b_c_d_e_f_g.txt",
		"name\x00with\x00nul.bin": "name_with_nul.bin",
		"tab\there.txt":           "tab_here.txt",
		// Hidden, trailing dots and spaces, device names.
		".bashrc":        "bashrc",
		"report.":        "report",
		"  padded.txt  ": "padded.txt",
		"CON.txt":        "_CON.txt",
		"nul":            "_nul",
		"com1.tar.gz":    "_com1.tar.gz",
		// Nothing usable left.
		"":    "file",
		"...": "file",
		"/":   "file",
		"???": "file",
	}
	for in, want := range cases {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 300) + ".qcow2"
	got := SafeName(long)
	if len(got) != 180 || !strings.HasSuffix(got, ".qcow2") {
		t.Errorf("long name not truncated with extension: %q (%d)", got, len(got))
	}
	// Truncation never splits a multi-byte character.
	multi := SafeName(strings.Repeat("é", 200) + ".txt")
	if !utf8.ValidString(multi) || len(multi) > 180 || !strings.HasSuffix(multi, ".txt") {
		t.Errorf("multi-byte truncation: %q (%d)", multi, len(multi))
	}
}

func TestOutboxName(t *testing.T) {
	if got := OutboxName("20261030T141502Z-jsmith-a3f9c1", 2, "vm image.qcow2", false); got != "vm image.qcow2" {
		t.Fatal(got)
	}
	if got := OutboxName("20261030T141502Z-jsmith-a3f9c1", 2, "vm image.qcow2", true); got != "20261030T141502Z-jsmith-a3f9c1_002_vm image.qcow2" {
		t.Fatal(got)
	}
	// The longest prefixed name plus ".sha256" fits in 255 bytes.
	id := "20261030T141502Z-" + strings.Repeat("a", 32) + "-a3f9c1"
	if n := len(OutboxName(id, 500, strings.Repeat("x", 400), true) + ".sha256"); n > 255 {
		t.Fatalf("name too long: %d", n)
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
