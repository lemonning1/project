package fingerprint

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := Load(filepath.Join("..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	return engine
}

func TestSampleMatchesContract(t *testing.T) {
	engine := loadTestEngine(t)
	items := loadSample(t)
	got := engine.IdentifyBatch(items)
	if len(got) != len(sampleExpected) {
		t.Fatalf("结果条数 = %d，想要 %d", len(got), len(sampleExpected))
	}
	for i := range sampleExpected {
		assertResult(t, i, got[i], sampleExpected[i])
	}

	raw, err := json.Marshal(got[:7])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != sampleGolden {
		t.Fatalf("前 7 条 JSON 与示例不一致\n得到: %s\n想要: %s", raw, sampleGolden)
	}
}

func TestOrderAndUnknownDoNotPanic(t *testing.T) {
	engine := loadTestEngine(t)
	items := []Input{
		{IP: "10.0.0.1", Port: 1, Banner: ""},
		{IP: "10.0.0.2", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{IP: "10.0.0.3", Port: 9, Banner: "QUIT\r\n"},
		{IP: "10.0.0.4", Port: 65535, Banner: string(make([]byte, maxBanner+100))},
	}
	got := engine.IdentifyBatch(items)
	if got[0].Protocol != "unknown" || got[0].IP != "10.0.0.1" {
		t.Fatalf("空 banner: %+v", got[0])
	}
	if got[1].Product != "OpenSSH" || got[1].IP != "10.0.0.2" {
		t.Fatalf("顺序被打乱: %+v", got[1])
	}
	if got[2].Protocol != "unknown" {
		t.Fatalf("QUIT 应是 unknown: %+v", got[2])
	}
	if got[3].Protocol == "" {
		t.Fatal("超长 banner 不应返回空协议")
	}
}

func TestLiteralEscapesMatchRawBytes(t *testing.T) {
	engine := loadTestEngine(t)
	literal := engine.Identify(Input{IP: "a", Port: 3306, Banner: `J\x00\x00\x00\n8.0.32\x00`})
	raw := engine.Identify(Input{IP: "a", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"})
	if literal.Version != "8.0.32" || raw.Version != "8.0.32" {
		t.Fatalf("literal=%+v raw=%+v", literal, raw)
	}
	if literal.Protocol != "MySQL" || raw.Protocol != "MySQL" {
		t.Fatalf("协议不一致 literal=%s raw=%s", literal.Protocol, raw.Protocol)
	}
}

func TestExtraBanners(t *testing.T) {
	engine := loadTestEngine(t)
	cases := []struct {
		banner   string
		protocol string
		product  string
		version  string
		osHint   string
	}{
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "SSH", "OpenSSH", "8.2p1", "Ubuntu"},
		{"SSH-2.0-OpenSSH_for_Windows_8.1", "SSH", "OpenSSH", "8.1", "Windows"},
		{"SSH-2.0-dropbear_2022.83", "SSH", "Dropbear", "2022.83", ""},
		{"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.43.v20210629)", "HTTP", "Jetty", "9.4.43.v20210629", ""},
		{"J\x00\x00\x00\n5.7.33-0ubuntu0.18.04.1\x00", "MySQL", "MySQL", "5.7.33", "Ubuntu"},
		{"J\x00\x00\x00\n5.5.5-10.11.6-MariaDB\x00", "MySQL", "MariaDB", "10.11.6", ""},
		{"# Server\r\nredis_version:6.2.6\r\n", "Redis", "Redis", "6.2.6", ""},
		{"220 ProFTPD 1.3.5 Server (Debian)", "FTP", "ProFTPD", "1.3.5", "Debian"},
		{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Win64) OpenSSL/1.1.1", "HTTP", "Apache", "2.4.52", "Windows"},
		{"220 mail.example.com ESMTP Postfix", "SMTP", "Postfix", "", ""},
		{"not a banner at all", "unknown", "", "", ""},
	}
	for _, tc := range cases {
		got := engine.Identify(Input{IP: "9.9.9.9", Port: 1, Banner: tc.banner})
		if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version || got.OSHint != tc.osHint {
			t.Errorf("banner %q\n got  %+v\n want protocol=%s product=%s version=%s os=%s",
				tc.banner, got, tc.protocol, tc.product, tc.version, tc.osHint)
		}
	}
}

func TestCustomRuleFileIsEnough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := []byte(`{
	  "schema_version": 1,
	  "rules": [{
	    "id": "acme",
	    "priority": 10,
	    "pattern": "Acme/([0-9.]+)",
	    "protocol": "HTTP",
	    "product": "Acme",
	    "version_group": 1,
	    "confidence": 0.77
	  }]
	}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Identify(Input{IP: "1.1.1.1", Port: 80, Banner: "Server: Acme/1.2.3"})
	if got.Product != "Acme" || got.Version != "1.2.3" || math.Abs(got.Confidence-0.77) > 1e-9 {
		t.Fatalf("自定义规则未生效: %+v", got)
	}
}

func TestRejectBrokenRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"bad","priority":1,"pattern":"(","protocol":"HTTP","confidence":0.5}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("坏正则应当拒绝启动")
	}
}

func loadSample(t *testing.T) []Input {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	var items []Input
	if err := json.Unmarshal(data, &items); err != nil {
		t.Fatal(err)
	}
	return items
}

func assertResult(t *testing.T, i int, got, want Result) {
	t.Helper()
	if got.IP != want.IP || got.Port != want.Port || got.Protocol != want.Protocol ||
		got.Product != want.Product || got.Version != want.Version || got.OSHint != want.OSHint ||
		math.Abs(got.Confidence-want.Confidence) > 1e-9 {
		t.Errorf("[%d] got %+v want %+v", i, got, want)
	}
}

const sampleGolden = `[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},{"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9},{"ip":"1.2.3.6","port":443,"protocol":"HTTP","product":"Apache","version":"2.4.57","os_hint":"","confidence":0.9},{"ip":"1.2.3.7","port":3306,"protocol":"MySQL","product":"MySQL","version":"8.0.32","os_hint":"","confidence":0.9},{"ip":"1.2.3.8","port":6379,"protocol":"Redis","product":"Redis","version":"","os_hint":"","confidence":0.7},{"ip":"1.2.3.9","port":21,"protocol":"FTP","product":"ProFTPD","version":"1.3.7","os_hint":"","confidence":0.9},{"ip":"1.2.3.10","port":8080,"protocol":"HTTP","product":"Jetty","version":"9.4.51","os_hint":"","confidence":0.85}]`

var sampleExpected = []Result{
	{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
	{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.10", Port: 8080, Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", OSHint: "", Confidence: 0.85},
	{IP: "1.2.3.11", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95},
	{IP: "1.2.3.12", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.9},
	{IP: "1.2.3.13", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.9},
	{IP: "1.2.3.14", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.15", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	{IP: "1.2.3.16", Port: 21, Protocol: "FTP", Product: "vsftpd", Version: "3.0.5", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.17", Port: 8443, Protocol: "HTTP", Product: "nginx", Version: "1.25.3", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.18", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "4.3", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.19", Port: 9999, Protocol: "TLS", Product: "", Version: "", OSHint: "", Confidence: 0.6},
	{IP: "1.2.3.20", Port: 8888, Protocol: "HTTP", Product: "Microsoft-IIS", Version: "10.0", OSHint: "", Confidence: 0.9},
	{IP: "1.2.3.21", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	{IP: "1.2.3.22", Port: 21, Protocol: "FTP", Product: "Pure-FTPd", Version: "", OSHint: "", Confidence: 0.75},
	{IP: "1.2.3.23", Port: 12345, Protocol: "unknown", Product: "", Version: "", OSHint: "", Confidence: 0},
}
