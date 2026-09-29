package main

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lemonning1/project/internal/fingerprint"
	"github.com/lemonning1/project/internal/httpapi"
)

func TestClientPrintsSample(t *testing.T) {
	engine, err := fingerprint.Load(filepath.Join("..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(httpapi.Handler(engine))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-input", filepath.Join("..", "..", "testdata", "sample.json"),
		"-server", srv.URL,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "识别完成：共 20 条，未知 1 条") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"product": "OpenSSH"`) || !strings.Contains(stdout.String(), `"protocol": "unknown"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}
