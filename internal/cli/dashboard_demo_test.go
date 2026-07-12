package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/app/ports"
)

// demoEnabled accepts exactly "1" and "true" — nothing else, including the
// differently-cased "TRUE" or look-alikes like "yes", opts into demo mode.
func TestDemoEnabled(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "true": true, "": false, "0": false, "yes": false, "TRUE": false} {
		if got := demoEnabled(v); got != want {
			t.Errorf("demoEnabled(%q) = %v, want %v", v, got, want)
		}
	}
}

// demoSetHome redirects the user home dir for a test across OSes, mirroring
// setHome in cli_test.go (an external test-package file not reachable from
// here, since demoEnabled is unexported and this test needs package cli).
func demoSetHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// demoFreePort binds :0 to learn an unused loopback address, then releases it
// so the dashboard can take it. Mirrors freePort in dashboard_test.go.
func demoFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// waitUntilListening polls addr until a TCP connection succeeds, failing the
// test if the dashboard never starts (it binds asynchronously in a goroutine).
func waitUntilListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("dashboard never started listening")
}

// TestDashboardDemoServesBuiltInDataset sets EYEBROW_DEMO=1 and checks that
// the dashboard serves the built-in demo dataset instead of scanning this
// machine, and announces it on stdout.
func TestDashboardDemoServesBuiltInDataset(t *testing.T) {
	demoSetHome(t, t.TempDir())
	t.Setenv("EYEBROW_DEMO", "1")
	addr := demoFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	app := New(out, errBuf)
	app.Clock = ports.ClockFunc(func() time.Time {
		return time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	})
	done := make(chan int, 1)
	go func() {
		done <- app.Execute(ctx, []string{"dashboard", "--addr", addr})
	}()

	waitUntilListening(t, addr)

	resp, err := http.Get("http://" + addr + "/api/scan")
	if err != nil {
		t.Fatalf("GET /api/scan: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /api/scan body: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, `"demo":true`) {
		t.Errorf("expected /api/scan body to contain %q, got: %s", `"demo":true`, body)
	}

	cancel()
	if code := <-done; code != ExitOK {
		t.Errorf("dashboard should exit 0 on graceful shutdown, got %d", code)
	}
	if !strings.Contains(out.String(), "serving DEMO data") {
		t.Errorf("stdout should announce demo mode:\n%s", out.String())
	}
}

// TestDashboardWithoutDemoEnvStaysOnRealData is the control: with
// EYEBROW_DEMO unset, the dashboard must not print the demo banner.
func TestDashboardWithoutDemoEnvStaysOnRealData(t *testing.T) {
	demoSetHome(t, t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{
  "mcpServers": {
    "local-tool": { "command": "./server.sh" }
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.sh"), []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	app := New(out, errBuf)
	app.Clock = ports.ClockFunc(func() time.Time {
		return time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	})
	done := make(chan int, 1)
	go func() {
		done <- app.Execute(ctx, []string{"dashboard", "--addr", "127.0.0.1:0", "--path", dir})
	}()
	cancel()
	if code := <-done; code != ExitOK {
		t.Fatalf("dashboard should exit 0 on graceful shutdown, got %d", code)
	}
	if strings.Contains(out.String(), "serving DEMO data") {
		t.Errorf("stdout should not announce demo mode when EYEBROW_DEMO is unset:\n%s", out.String())
	}
}
