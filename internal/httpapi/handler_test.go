package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lemonning1/project/internal/fingerprint"
)

func TestHealthAndFingerprint(t *testing.T) {
	engine, err := fingerprint.Load(filepath.Join("..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler(engine)

	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthResp := httptest.NewRecorder()
	handler.ServeHTTP(healthResp, healthReq)
	if healthResp.Code != http.StatusOK {
		t.Fatalf("health = %d body=%s", healthResp.Code, healthResp.Body.String())
	}
	var healthBody map[string]any
	if err := json.Unmarshal(healthResp.Body.Bytes(), &healthBody); err != nil {
		t.Fatal(err)
	}
	if healthBody["status"] != "ok" {
		t.Fatalf("health body = %s", healthResp.Body.String())
	}

	sample, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(sample))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("fingerprint = %d body=%s", resp.Code, resp.Body.String())
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(resp.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 20 {
		t.Fatalf("len=%d", len(results))
	}
	if results[0].Product != "OpenSSH" || results[0].Version != "8.9p1" || results[0].OSHint != "Ubuntu" {
		t.Fatalf("first = %+v", results[0])
	}
	if results[19].Protocol != "unknown" || results[19].Confidence != 0 {
		t.Fatalf("last = %+v", results[19])
	}
}

func TestBadItemDoesNotFailBatch(t *testing.T) {
	engine, err := fingerprint.Load(filepath.Join("..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`[
	  {"ip":"1.1.1.1","port":"bad","banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	  {"ip":"1.1.1.2","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(body))
	resp := httptest.NewRecorder()
	Handler(engine).ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(resp.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("len=%d", len(results))
	}
	if results[0].Protocol != "unknown" {
		t.Fatalf("坏记录应降级为 unknown: %+v", results[0])
	}
	if results[1].Product != "OpenSSH" {
		t.Fatalf("好记录被连累: %+v", results[1])
	}
}

func TestRejectNonArray(t *testing.T) {
	engine, err := fingerprint.Load(filepath.Join("..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewBufferString(`{"ip":"1.1.1.1"}`))
	resp := httptest.NewRecorder()
	Handler(engine).ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.Code)
	}
}

func TestEmptyEngineIsNotReady(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp := httptest.NewRecorder()
	Handler(nil).ServeHTTP(resp, req)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", resp.Code)
	}
}

func TestHealthURL(t *testing.T) {
	if got := healthURL(":8080"); got != "http://127.0.0.1:8080/health" {
		t.Fatal(got)
	}
	if got := healthURL("0.0.0.0:9090"); got != "http://127.0.0.1:9090/health" {
		t.Fatal(got)
	}
}
