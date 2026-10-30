package web

import (
	"strings"
	"testing"
)

func TestRenderInstructionsEscapes(t *testing.T) {
	out := string(RenderInstructions("# Title <script>alert(1)</script>\n\n- item **bold** & <img src=x onerror=alert(1)>\n1. step\n\nPara with \"quotes\""))
	for _, bad := range []string{"<script", "<img", "onerror=alert(1)>"} {
		if strings.Contains(out, bad) {
			t.Fatalf("unescaped %q in %s", bad, out)
		}
	}
	for _, want := range []string{"<h2>Title &lt;script&gt;", "<ul>\n<li>item <strong>bold</strong> &amp; &lt;img", "<ol>\n<li>step</li>", "<p>Para with &#34;quotes&#34;</p>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
