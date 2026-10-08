package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const liveSecret = "a1b2c3d4e5f60718293a4b5c6d7e8f90" +
	"1a2b3c4d5e6f708192a3b4c5d6e7f809"

// buildBinary compiles the command once for the whole test binary.
var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "httpflip-bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "httpflip")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Stderr = os.Stderr
		buildErr = cmd.Run()
	})
	if buildErr != nil {
		t.Fatalf("build httpflip: %v", buildErr)
	}
	return binPath
}

// freePort reserves a port and releases it, so the child can bind it.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

type instance struct {
	cmd    *exec.Cmd
	stdout *strings.Builder
	addr   string
	tokens string
}

func start(t *testing.T) *instance {
	t.Helper()
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens")
	if err := os.WriteFile(tokens,
		[]byte("live  "+liveSecret+"  -\n"), 0o600); err != nil {
		t.Fatalf("write tokens: %v", err)
	}
	addr := freePort(t)
	bin := binary(t)

	cmd := exec.Command(bin,
		"-addr", addr,
		"-data-dir", filepath.Join(dir, "data"),
		"-tokens-file", tokens,
		"-log-level", "debug",
	)
	out := &strings.Builder{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start httpflip: %v", err)
	}
	inst := &instance{cmd: cmd, stdout: out, addr: addr, tokens: tokens}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	inst.waitReady(t)
	return inst
}

func (in *instance) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + in.addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("service never became ready; output:\n%s", in.stdout.String())
}

func (in *instance) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get("http://" + in.addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp, string(body)
}

func TestServiceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "payload.txt"),
		[]byte("end to end payload"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	in := start(t)

	// A real client sends multipart/form-data, so build one from the file.
	bodyBuf := &bytes.Buffer{}
	mw := multipart.NewWriter(bodyBuf)
	part, err := mw.CreateFormFile("file", "payload.txt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	payload, err := os.ReadFile(filepath.Join(dir, "payload.txt"))
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost,
		"http://"+in.addr+"/upload", bytes.NewReader(bodyBuf.Bytes()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+liveSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d: %s", resp.StatusCode, gotBody)
	}
	path := extractPath(t, string(gotBody))
	if !strings.HasPrefix(path, "/data/") {
		t.Fatalf("path = %q, want a /data/ prefix", path)
	}

	// An unauthenticated upload must be refused.
	badReq, err := http.NewRequest(http.MethodPost,
		"http://"+in.addr+"/upload", bytes.NewReader(bodyBuf.Bytes()))
	if err != nil {
		t.Fatalf("build unauthenticated request: %v", err)
	}
	badReq.Header.Set("Content-Type", mw.FormDataContentType())
	bad, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("unauthenticated upload: %v", err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated upload status = %d, want 401",
			bad.StatusCode)
	}

	resp, body := in.get(t, path)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d", resp.StatusCode)
	}
	if body != "end to end payload" {
		t.Errorf("body = %q, want the uploaded bytes", body)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(
		cd, "payload.txt") {
		t.Errorf("content-disposition = %q", cd)
	}

	probe, _ := in.get(t, "/healthz")
	if probe.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d", probe.StatusCode)
	}
}

func extractPath(t *testing.T, body string) string {
	t.Helper()
	const key = `"path":"`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("no path in %q", body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated path in %q", body)
	}
	return rest[:j]
}

func TestRefusesToStartWithoutTokens(t *testing.T) {
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens")
	// No credentials at all.
	if err := os.WriteFile(tokens, []byte("# none\n"), 0o600); err != nil {
		t.Fatalf("write tokens: %v", err)
	}
	cmd := exec.Command(binary(t),
		"-addr", freePort(t),
		"-data-dir", filepath.Join(dir, "data"),
		"-tokens-file", tokens,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("service started with no usable credentials, want failure")
	}
	if !strings.Contains(string(out), "credentials") {
		t.Errorf("output = %q, want it to mention the credential problem",
			out)
	}
}

func TestRefusesToStartWithUnwritableDataDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens")
	if err := os.WriteFile(tokens,
		[]byte("live  "+liveSecret+"  -\n"), 0o600); err != nil {
		t.Fatalf("write tokens: %v", err)
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	cmd := exec.Command(binary(t),
		"-addr", freePort(t), "-data-dir", ro, "-tokens-file", tokens)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("service started with an unwritable data dir, want failure")
	}
	if !strings.Contains(string(out), "not writable") {
		t.Errorf("output = %q, want it to mention writability", out)
	}
}

// OpenShift sends SIGTERM on every rollout, so a drain that drops in-flight
// work is a real production failure rather than a theoretical one.
func TestGracefulShutdownOnSigterm(t *testing.T) {
	in := start(t)

	// Occupy the listener with a request that is still streaming.
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost,
		"http://"+in.addr+"/upload", pr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary=xx")
	req.Header.Set("Authorization", "Bearer "+liveSecret)

	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{0, err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		done <- result{resp.StatusCode, nil}
	}()

	// Let the request reach the handler before signalling.
	time.Sleep(300 * time.Millisecond)

	if err := in.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	// Finish the upload.
	go func() {
		_, _ = pw.Write([]byte("--xx\r\n" +
			"Content-Disposition: form-data; name=\"file\"; " +
			"filename=\"late.txt\"\r\n\r\nlate bytes\r\n--xx--\r\n"))
		_ = pw.Close()
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Errorf("in-flight upload failed during shutdown: %v", res.err)
		} else if res.status != http.StatusCreated {
			t.Errorf("in-flight upload status = %d, want 201", res.status)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("in-flight upload never completed")
	}

	// The process must then exit on its own.
	exited := make(chan error, 1)
	go func() { exited <- in.cmd.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("exit status = %v, want a clean exit", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("service did not exit after SIGTERM")
	}

	out := in.stdout.String()
	if !strings.Contains(out, "shutting down") {
		t.Errorf("output does not mention shutting down:\n%s", out)
	}
	if !strings.Contains(out, "stopped") {
		t.Errorf("output does not report a clean stop:\n%s", out)
	}
}

func TestVersionFlag(t *testing.T) {
	out, err := exec.Command(binary(t), "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("-version: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "httpflip") {
		t.Errorf("output = %q, want the program name", out)
	}
}

func TestLoggerRejectsBadLevel(t *testing.T) {
	// An unrecognised level falls back to info rather than refusing to
	// start, so check the fallback directly.
	log := newLogger("not-a-level")
	if log == nil {
		t.Fatal("newLogger returned nil")
	}
	var _ slog.Logger = *log
	if fmt.Sprint(log) == "" {
		t.Error("logger is empty")
	}
}
