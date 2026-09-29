// Package httpapi 提供指纹服务的 HTTP 接口。
// 识别失败写入 unknown 结果；只有请求本身不合法时才返回 4xx。
package httpapi

import (
	"encoding/json"
	"errors"
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
		if engine == nil || engine.Len() == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "规则尚未加载",
			})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
					"error": "请求体过大",
				})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "读取请求体失败",
			})
			return
		}

		var raws []json.RawMessage
		if err := json.Unmarshal(body, &raws); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "请求体必须是 JSON 数组",
			})
			return
		}
		if len(raws) > maxItems {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("单次最多提交 %d 条", maxItems),
			})
			return
		}

		items := make([]fingerprint.Input, len(raws))
		bad := make([]bool, len(raws))
		for i, raw := range raws {
			if string(raw) == "null" {
				bad[i] = true
				continue
			}
			if err := json.Unmarshal(raw, &items[i]); err != nil {
				bad[i] = true
			}
		}

		results := engine.IdentifyBatch(items)
		for i := range results {
			if bad[i] {
				results[i] = fingerprint.Unknown(items[i])
			}
		}
		writeJSON(w, http.StatusOK, results)
	}
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
