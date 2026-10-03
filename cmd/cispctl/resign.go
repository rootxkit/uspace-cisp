package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// keyRingSigner signs a snapshot's bytes with the ring's active key.
type keyRingSigner struct {
	keys *jws.KeyRing
	now  time.Time
}

func (s keyRingSigner) Sign(_ context.Context, body []byte) (string, error) {
	return s.keys.SignDetached(body, s.now)
}

// resignCurrent signs each named dataset's current snapshot again with
// the active key (docs/PLAN.md section 15 Q50, after a key compromise):
// append-only, the bytes and the ETag unchanged. The api serves the new
// signature once it reloads the snapshot (a restart).
func resignCurrent(ctx context.Context, args, environ []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("resign-current", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataset := fs.String("dataset", "", "the dataset to re-sign, or all")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dataset == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	datasets := []publication.Dataset{publication.Dataset(*dataset)}
	if *dataset == "all" {
		datasets = publication.Datasets
	} else if !datasets[0].Valid() {
		_, _ = fmt.Fprintf(stderr, "cispctl: %q is not a dataset\n", *dataset)
		return exitUsage
	}
	cfg, err := config.LoadCtl(environ)
	if printProblems(stderr, "cispctl", err) {
		return exitConfig
	}
	if cfg.SigningKeyFile == "" || cfg.SigningKID == "" {
		_, _ = fmt.Fprintf(stderr, "cispctl: resign-current: %s and %s must name the active key\n", config.EnvSigningKeyFile, config.EnvSigningKID)
		return exitConfig
	}
	keys, err := jws.ReadKeyRing(cfg.SigningKeyFile, cfg.SigningKID, cfg.SigningKeyPrevFile, cfg.SigningKIDPrev)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: resign-current: signing key: %v\n", err)
		return exitConfig
	}
	pool, code := openTree(ctx, store.TreeRelational, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	st := store.New(pool, store.Options{})
	signer := keyRingSigner{keys: keys, now: now}
	for _, ds := range datasets {
		rep, err := st.ResignCurrent(ctx, ds, signer, keys.ActiveKID(), now)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cispctl: %s: %v; nothing was changed\n", ds, err)
			return exitFailed
		}
		if rep.Version == 0 {
			_, _ = fmt.Fprintf(stdout, "%s: never published; nothing to re-sign\n", ds)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "%s version %d: re-signed with kid %s (bytes and ETag unchanged)\n", ds, rep.Version, rep.KID)
	}
	_, _ = fmt.Fprintln(stdout, "restart api so it serves the new signatures")
	return exitOK
}
