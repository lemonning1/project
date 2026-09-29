// Command client 读取本地 JSON 文件，交给指纹服务，并把识别结果打到标准输出。
// 识别结果里出现 unknown 仍视为本次调用成功；连不上服务或请求被拒绝时才非 0 退出。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lemonning1/project/internal/fingerprint"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fingerprint-client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", os.Getenv("FINGERPRINT_INPUT"), "本地 JSON 文件，内容为扫描记录数组")
	server := fs.String("server", firstNonEmpty(os.Getenv("FINGERPRINT_SERVER"), "http://127.0.0.1:8080"), "指纹服务地址")
	timeout := fs.Duration("timeout", 30*time.Second, "单次请求超时")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *input == "" {
		fmt.Fprintln(stderr, "缺少输入文件：使用 -input 或环境变量 FINGERPRINT_INPUT")
		fs.PrintDefaults()
		return 2
	}

	payload, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(stderr, "读取输入文件失败: %v\n", err)
		return 2
	}

	endpoint := strings.TrimRight(*server, "/") + "/fingerprint"
	body, status, err := postFingerprint(endpoint, payload, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "请求指纹服务失败: %v\n", err)
		return 2
	}
	if status != http.StatusOK {
		fmt.Fprintf(stderr, "指纹服务返回 %d: %s\n", status, strings.TrimSpace(string(body)))
		return 2
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(body, &results); err != nil {
		fmt.Fprintf(stderr, "解析识别结果失败: %v\n", err)
		return 2
	}

	unknown := 0
	for _, item := range results {
		if item.Protocol == "unknown" {
			unknown++
		}
	}
	fmt.Fprintf(stderr, "识别完成：共 %d 条，未知 %d 条\n", len(results), unknown)

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintf(stderr, "写出结果失败: %v\n", err)
		return 2
	}
	return 0
}

func postFingerprint(endpoint string, payload []byte, timeout time.Duration) ([]byte, int, error) {
	client := &http.Client{Timeout: timeout}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "banner-fingerprint-client")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		return body, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
