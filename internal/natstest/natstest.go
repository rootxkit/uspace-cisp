// Package natstest runs a real NATS JetStream broker in a docker
// container that a test creates, starts, stops and starts again: the
// broker absent at a start and taken away during a run for real, never a
// mock that returns an error (LESSONS E-02). Only tests import it. It
// needs the docker CLI; Require skips (and says so) without it.
package natstest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Image is the broker image, the one deploy/compose.dev.yml and CI run.
const Image = "nats:2-alpine"

// Broker is one container on a fixed local port, so the address stays
// the same across stop and start.
type Broker struct {
	t    testing.TB
	name string
	addr string
}

// Require skips the test when the docker CLI is missing or the daemon
// does not answer: the skip is reported as one (E-04), never as a pass.
func Require(t testing.TB) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH: the broker outage cannot be run for real here")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("the docker daemon does not answer (%v: %s): the broker outage cannot be run for real here", err, strings.TrimSpace(string(out)))
	}
}

func freePort(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// New creates the container without starting it: the broker is absent
// until Start. The container is removed when the test ends.
func New(t testing.TB) *Broker {
	t.Helper()
	Require(t)
	var b [4]byte
	_, _ = rand.Read(b[:])
	br := &Broker{t: t, name: "cisp-test-nats-" + hex.EncodeToString(b[:]), addr: freePort(t)}
	_, port, _ := net.SplitHostPort(br.addr)
	br.docker(2*time.Minute, "create", "--name", br.name, "-p", "127.0.0.1:"+port+":4222", Image, "-js")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", br.name).Run() //nolint:gosec // G204: the name is generated here, the command fixed
	})
	return br
}

// URL is the broker's nats:// URL.
func (b *Broker) URL() string { return "nats://" + b.addr }

// Name is the container's name.
func (b *Broker) Name() string { return b.name }

func (b *Broker) docker(timeout time.Duration, args ...string) {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() //nolint:gosec // G204: docker verbs of this file and a generated name
	if err != nil {
		b.t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// Start starts the container and waits until the broker accepts a TCP
// connection.
func (b *Broker) Start() {
	b.t.Helper()
	b.docker(time.Minute, "start", b.name)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", b.addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.t.Fatalf("broker %s did not open %s within 30 s", b.name, b.addr)
}

// Stop stops the container (docker stop: the broker goes away as it does
// in production, its connections closed).
func (b *Broker) Stop() {
	b.t.Helper()
	b.docker(time.Minute, "stop", "-t", "2", b.name)
}
