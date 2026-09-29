// Command server 加载外部规则并提供指纹识别 HTTP 服务。
// 容器健康检查执行：/server healthcheck
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lemonning1/project/internal/fingerprint"
	"github.com/lemonning1/project/internal/httpapi"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		addr := env("LISTEN_ADDR", ":8080")
		if err := httpapi.Check(addr); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	listen := flag.String("listen", env("LISTEN_ADDR", ":8080"), "监听地址")
	rulesPath := flag.String("rules", env("RULES_PATH", "rules/fingerprints.json"), "规则文件路径")
	flag.Parse()

	engine, err := fingerprint.Load(*rulesPath)
	if err != nil {
		log.Fatalf("加载规则失败 path=%s err=%v", *rulesPath, err)
	}
	log.Printf("规则已加载 path=%s count=%d", engine.Source(), engine.Len())

	srv := &http.Server{
		Addr:              *listen,
		Handler:           logRequests(httpapi.Handler(engine)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("监听 %s", *listen)
		errCh <- srv.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("关闭服务: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("监听失败: %v", err)
		}
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
