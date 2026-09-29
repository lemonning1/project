// Package httpapi 提供指纹服务的 HTTP 接口。
// /fingerprint 对任何请求体都返回 200：认不出或解析不了的记录变成 unknown，空结果是 []。
package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lemonning1/project/internal/fingerprint"
)

const (
	maxBody  = 4 << 20
	maxItems = 10000
)

// Handler 挂上 GET /health 和 POST /fingerprint。
func Handler(engine *fingerprint.Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health(engine))
	mux.HandleFunc("POST /fingerprint", fingerprintHandler(engine))
	return mux
}

func health(engine *fingerprint.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		n := 0
		if engine != nil {
			n = engine.Len()
		}
		if n == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":       "not_ready",
				"rules_loaded": 0,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"rules_loaded": n,
		})
	}
}

func fingerprintHandler(engine *fingerprint.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, identifyRequest(engine, r))
	}
}

// identifyRequest 保证不把解析失败变成非 200。调用方拿到的切片始终非 nil。
func identifyRequest(engine *fingerprint.Engine, r *http.Request) (results []fingerprint.Result) {
	results = []fingerprint.Result{}
	defer func() {
		if recover() != nil {
			results = []fingerprint.Result{}
		}
	}()
	if r == nil || r.Body == nil || engine == nil || engine.Len() == 0 {
		return results
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || int64(len(body)) > maxBody {
		return results
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return results
	}

	switch body[0] {
	case '[':
		return identifyArray(engine, body)
	case '{':
		var item fingerprint.Input
		if err := json.Unmarshal(body, &item); err != nil {
			return results
		}
		return engine.IdentifyBatch([]fingerprint.Input{item})
	default:
		return results
	}
}

func identifyArray(engine *fingerprint.Engine, body []byte) []fingerprint.Result {
	var raws []json.RawMessage
	if err := json.Unmarshal(body, &raws); err != nil {
		return []fingerprint.Result{}
	}
	if len(raws) > maxItems {
		raws = raws[:maxItems]
	}
	items := make([]fingerprint.Input, len(raws))
	bad := make([]bool, len(raws))
	for i, raw := range raws {
		if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			bad[i] = true
			continue
		}
		if err := json.Unmarshal(raw, &items[i]); err != nil {
			bad[i] = true
		}
	}
	results := engine.IdentifyBatch(items)
	if results == nil {
		results = []fingerprint.Result{}
	}
	for i := range results {
		if bad[i] {
			results[i] = fingerprint.Unknown(items[i])
		}
	}
	return results
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// Check 供容器健康检查调用：连到本进程的 /health，规则已加载才返回 nil。
func Check(listenAddr string) error {
	url := healthURL(listenAddr)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health status %d", resp.StatusCode)
	}
	return nil
}

func healthURL(listenAddr string) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "http://127.0.0.1:8080/health"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/health"
}
