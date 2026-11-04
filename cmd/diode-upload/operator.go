package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/nc-intezra/docker-secure-upload/internal/control"
)

// operator runs the held-file commands against the running service.
func operator(cmd string, args []string) int {
	c := control.NewClient(envOr("CONTROL_SOCKET", "/tmp/diode-upload.sock"))
	if cmd == "held" {
		items, err := c.Held()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(items) == 0 {
			fmt.Println("No held or quarantined files.")
			return 0
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSTATE\tUSER\tSIZE\tRECEIVED\tNAME\tREASON")
		for _, it := range items {
			reason := it.Reason
			if it.Signature != "" {
				reason += " [" + it.Signature + "]"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", it.ID, it.State, it.Username, it.Size,
				it.ReceivedAt.Format("2006-01-02 15:04Z"), it.OutboxName, reason)
		}
		tw.Flush()
		return 0
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	by := fs.String("by", "", "your name, for the audit log (required)")
	reason := fs.String("reason", "", "why, for the audit log (required)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: diode-upload %s ID --by NAME --reason TEXT\n", cmd)
		fs.PrintDefaults()
	}
	// Accept the ID before or after the flags.
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if id == "" && fs.NArg() == 1 {
		id = fs.Arg(0)
	} else if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	if id == "" || *by == "" || *reason == "" {
		fs.Usage()
		return 2
	}
	req := control.Request{ID: id, By: *by, Reason: *reason}
	var it control.Item
	var err error
	if cmd == "release" {
		fmt.Println("Checking the file's SHA-256 before release; large files take a few minutes...")
		it, err = c.Release(req)
	} else {
		it, err = c.Delete(req)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "refused:", err)
		return 1
	}
	if cmd == "release" {
		fmt.Printf("Released %s to the outbox as %s (state %s).\n", it.ID, it.OutboxName, it.State)
	} else {
		fmt.Printf("Deleted %s (%s).\n", it.ID, it.OriginalName)
	}
	return 0
}
