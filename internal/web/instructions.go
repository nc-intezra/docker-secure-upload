package web

import (
	"html/template"
	"os"
	"strings"
)

// DefaultInstructions is shown when no instructions file is mounted.
const DefaultInstructions = `# How to send files across

1. Enter your username. It is recorded with every file you send.
2. Drag files onto the drop area, or choose **Browse** to pick them.
3. Your files keep their names on the other side. Tick **Add the batch ID and my username to file names** only if you want each name to start with the date, your username and a batch number.
4. Select **Upload**. Large files are sent in pieces and resume automatically if the connection drops; keep this page open until every file shows a result.
5. Write down the SHA-256 shown for each file. The receiving side gets the same value in a .sha256 file next to it.

## What happens to your files

- Every file is checked for viruses before it is passed on.
- Files that fail the check are blocked and do not cross. An administrator can review them.
- Very large files (over about 4 GB) cannot be fully scanned. They are held until an administrator checks and releases them, so allow extra time and tell the administrator when you send one.
- Characters that are not allowed in file names on Windows or Linux (such as ? * : < > | and quotes) are replaced with _. The page shows the new name when this happens.
- If a file with the same name is still waiting to cross, yours waits until it has gone, so nothing is overwritten.
- If you send a lot at once, some files may show "Waiting for your earlier uploads to finish". They start on their own; keep the page open.
`

// LoadInstructions reads path, falling back to DefaultInstructions.
func LoadInstructions(path string) template.HTML {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return RenderInstructions(DefaultInstructions)
	}
	return RenderInstructions(string(b))
}

// RenderInstructions turns a small, safe subset of Markdown into HTML:
// "#"/"##" headings, "-"/"*" bullets, "1." numbered items, paragraphs and
// **bold**. All text is HTML-escaped first; no raw HTML or links are
// supported, so the output cannot carry script.
func RenderInstructions(md string) template.HTML {
	var b strings.Builder
	list := "" // "ul", "ol" or ""
	var para []string

	flushPara := func() {
		if len(para) > 0 {
			b.WriteString("<p>" + inline(strings.Join(para, " ")) + "</p>\n")
			para = nil
		}
	}
	closeList := func() {
		if list != "" {
			b.WriteString("</" + list + ">\n")
			list = ""
		}
	}
	openList := func(kind string) {
		if list != kind {
			closeList()
			b.WriteString("<" + kind + ">\n")
			list = kind
		}
	}

	for _, raw := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			flushPara()
			closeList()
		case strings.HasPrefix(line, "## "):
			flushPara()
			closeList()
			b.WriteString("<h3>" + inline(line[3:]) + "</h3>\n")
		case strings.HasPrefix(line, "# "):
			flushPara()
			closeList()
			b.WriteString("<h2>" + inline(line[2:]) + "</h2>\n")
		case strings.HasPrefix(line, "- "), strings.HasPrefix(line, "* "):
			flushPara()
			openList("ul")
			b.WriteString("<li>" + inline(line[2:]) + "</li>\n")
		case numbered(line) > 0:
			flushPara()
			openList("ol")
			b.WriteString("<li>" + inline(line[numbered(line):]) + "</li>\n")
		default:
			closeList()
			para = append(para, line)
		}
	}
	flushPara()
	closeList()
	return template.HTML(b.String()) //nolint:gosec // every text run is escaped in inline()
}

// numbered returns the length of a "12. " prefix, or 0.
func numbered(line string) int {
	i := 0
	for i < len(line) && i < 3 && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i > 0 && strings.HasPrefix(line[i:], ". ") {
		return i + 2
	}
	return 0
}

// inline escapes text and then converts **bold** pairs.
func inline(s string) string {
	esc := template.HTMLEscapeString(s)
	parts := strings.Split(esc, "**")
	if len(parts)%2 == 0 { // unbalanced: leave the asterisks alone
		return esc
	}
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			b.WriteString("<strong>" + p + "</strong>")
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}
