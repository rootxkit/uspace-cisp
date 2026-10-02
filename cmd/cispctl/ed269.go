package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"

	"github.com/rootxkit/uspace-cisp/internal/dataset"
)

// maxConvertBytes is the default largest input of ed269 convert: the
// CISP_MAX_PUBLICATION_BYTES default, so a file convert accepts is one
// PUT accepts by size.
const maxConvertBytes = 32 << 20

// ed269Convert maps one document between ED-269 and ED-318 offline,
// through the same uspace-core mapping the api runs (WP-12): --to ed318
// reads ED-269 strictly and maps it (ed318.FromED269, no metadata
// added), --to ed269 exports ED-318 (ed318.ToED269). The output goes to
// stdout; every problem goes to stderr as "field: reason" and the exit
// code is 1. Mapping warnings (members carried under
// extendedProperties.ed269) go to stderr with exit 0.
func ed269Convert(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "convert" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	fs := flag.NewFlagSet("ed269 convert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.String("to", "", "ed318 (input ED-269) or ed269 (input ED-318)")
	lang := fs.String("lang", dataset.DefaultED269Lang, "language of ED-269's single-string texts")
	maxBytes := fs.Int("max-bytes", maxConvertBytes, "largest input accepted")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || (*to != "ed318" && *to != "ed269") || *maxBytes <= 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	body, err := readBody(stdin, int64(*maxBytes))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	var out []byte
	if *to == "ed318" {
		imp, probs := dataset.FromED269(body, *maxBytes, dataset.ED269Meta{Lang: *lang})
		if probs != nil {
			printED269Problems(stderr, probs)
			return exitFailed
		}
		for _, w := range imp.Warnings {
			_, _ = fmt.Fprintf(stderr, "warning: %s: %s\n", w.Field, w.Reason)
		}
		out = imp.Body
	} else {
		out, err = dataset.ToED269(body, *maxBytes, *lang)
		var probs *ed269.Problems
		var fe *core.FieldError
		switch {
		case errors.As(err, &probs):
			printED269Problems(stderr, probs)
			return exitFailed
		case errors.As(err, &fe):
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", fe.Field, fe.Reason)
			return exitFailed
		case err != nil:
			_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
			return exitFailed
		}
	}
	if _, err := stdout.Write(append(out, '\n')); err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	return exitOK
}

func printED269Problems(w io.Writer, probs *ed269.Problems) {
	for _, p := range probs.List {
		_, _ = fmt.Fprintf(w, "%s: %s\n", p.Field, p.Reason)
	}
	if probs.Truncated > 0 {
		_, _ = fmt.Fprintf(w, "and %d more problems\n", probs.Truncated)
	}
}
