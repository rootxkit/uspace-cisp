//go:build integration

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

type oldKeySigner struct{}

func (oldKeySigner) Sign(context.Context, []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"cisp-old"}`)) + "..c2ln", nil
}

// kidOf is the kid in a compact detached JWS's protected header.
func kidOf(t *testing.T, sig string) string {
	t.Helper()
	head, _, _ := strings.Cut(sig, ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		t.Fatalf("header of %q: %v", sig, err)
	}
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.KID
}

// resign-current --dataset all re-signs every published dataset's
// current snapshot with the active key: the served signature then names
// the new kid while the ETag stays; a dataset never published says so.
// Without a signing key it refuses before connecting (S5, Q50).
func TestResignCurrentCommand(t *testing.T) {
	ctx := context.Background()
	s := dbPool(t)
	body := []byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-03T00:00:00Z","ussps":[],"n":"resign-` + store.NewID(time.Now()) + `"}`)
	res, err := s.PublishTx(ctx, store.PublishInput{Dataset: publication.DatasetUSSPList, Body: body, ContentType: "application/json",
		PublisherClientID: "authority-01", Reason: publication.ReasonPublication}, oldKeySigner{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot(ctx, publication.DatasetUSSPList, res.Version)
	if err != nil || kidOf(t, before.CISPSignature) != "cisp-old" {
		t.Fatalf("published under %q: %v", before.CISPSignature, err)
	}

	key := authtest.Key(t, "cisp-resign", 3072)
	pemBytes, err := jws.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(testEnv(t), "CISP_SIGNING_KEY_FILE="+keyFile, "CISP_SIGNING_KID=cisp-new")
	code, out, errOut := runCtl([]string{"resign-current", "--dataset", "all"}, env)
	if code != exitOK {
		t.Fatalf("resign-current = %d %q %q", code, out, errOut)
	}
	t.Log(strings.TrimSpace(out))
	versions, err := s.CurrentVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, ds := range publication.Datasets {
		v := versions[ds]
		if v == 0 {
			if !strings.Contains(out, string(ds)+": never published; nothing to re-sign") {
				t.Errorf("%s: %q", ds, out)
			}
			continue
		}
		if !strings.Contains(out, string(ds)+" version ") || !strings.Contains(out, "re-signed with kid cisp-new") {
			t.Errorf("%s: %q", ds, out)
		}
		snap, err := s.Snapshot(ctx, ds, v)
		if err != nil {
			t.Fatal(err)
		}
		if kidOf(t, snap.CISPSignature) != "cisp-new" {
			t.Errorf("%s version %d is served under %q", ds, v, kidOf(t, snap.CISPSignature))
		}
	}
	after, _ := s.Snapshot(ctx, publication.DatasetUSSPList, res.Version)
	if after.ETag != before.ETag || !bytes.Equal(after.BodyGz, before.BodyGz) {
		t.Error("re-signing changed the snapshot")
	}
	zr, err := gzip.NewReader(bytes.NewReader(after.BodyGz))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jws.NewDetachedVerifier(ctx, jws.KeySource{Publisher: "cisp", Keys: coreauth.IssuerConfig{Keys: authtest.PublicSet(t, map[string]*rsa.PrivateKey{"cisp-new": key})}},
		time.Hour, jws.Options{MaxPayloadBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, after.CISPSignature, raw); err != nil {
		t.Errorf("the new signature does not verify over the stored bytes: %v", err)
	}
	if code, _, errOut := runCtl([]string{"resign-current", "--dataset", "zones"}, testEnv(t)); code != exitConfig || !strings.Contains(errOut, "CISP_SIGNING_KEY_FILE") {
		t.Errorf("without a signing key = %d %q", code, errOut)
	}
}
