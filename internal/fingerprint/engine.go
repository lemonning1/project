// Package fingerprint 把扫描得到的 banner 文本匹配成协议、软件、版本和系统线索。
// 匹配规则来自外部 JSON 文件，本包只实现「按优先级做正则抽取」。
package fingerprint

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxBanner = 64 * 1024
	unknown   = "unknown"
)

// Input 是一条扫描原始记录。端口不参与匹配，只原样带回。
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result 是一条识别结果。认不出来时 Protocol 为 unknown，其余识别字段为空，Confidence 为 0。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// MarshalJSON 把置信度写成最短十进制，避免 0.9 变成一长串二进制尾数。
func (r Result) MarshalJSON() ([]byte, error) {
	conf := strconv.FormatFloat(r.Confidence, 'f', -1, 64)
	return json.Marshal(struct {
		IP         string          `json:"ip"`
		Port       int             `json:"port"`
		Protocol   string          `json:"protocol"`
		Product    string          `json:"product"`
		Version    string          `json:"version"`
		OSHint     string          `json:"os_hint"`
		Confidence json.RawMessage `json:"confidence"`
	}{
		IP:         r.IP,
		Port:       r.Port,
		Protocol:   r.Protocol,
		Product:    r.Product,
		Version:    r.Version,
		OSHint:     r.OSHint,
		Confidence: json.RawMessage(conf),
	})
}

// Unknown 构造一条「认不出来」的结果，调用方用它保证单条失败不会变成请求失败。
func Unknown(in Input) Result {
	return Result{
		IP:         in.IP,
		Port:       in.Port,
		Protocol:   unknown,
		Confidence: 0,
	}
}

// Rule 是规则文件中的一条指纹。具体产品名、版本抽取位置和置信度都写在文件里。
type Rule struct {
	ID           string  `json:"id"`
	Description  string  `json:"description,omitempty"`
	Priority     int     `json:"priority"`
	Pattern      string  `json:"pattern"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product,omitempty"`
	ProductGroup int     `json:"product_group,omitempty"`
	VersionGroup int     `json:"version_group,omitempty"`
	OSHint       string  `json:"os_hint,omitempty"`
	OSHintGroup  int     `json:"os_hint_group,omitempty"`
	Confidence   float64 `json:"confidence"`
	Enabled      *bool   `json:"enabled,omitempty"`
}

type ruleFile struct {
	SchemaVersion int               `json:"schema_version"`
	OSAliases     map[string]string `json:"os_aliases"`
	Rules         []Rule            `json:"rules"`
}

type compiledRule struct {
	rule Rule
	re   *regexp.Regexp
}

// Engine 在启动时编译规则，之后只读，可以并发调用。
type Engine struct {
	rules   []compiledRule
	aliases map[string]string
	source  string
}

// Load 读取并编译规则文件。正则写错、置信度越界或一条规则都没有时返回错误，进程不应带病启动。
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件: %w", err)
	}
	var file ruleFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("解析规则文件: %w", err)
	}
	if file.SchemaVersion != 0 && file.SchemaVersion != 1 {
		return nil, fmt.Errorf("不支持的规则 schema_version=%d", file.SchemaVersion)
	}

	aliases := make(map[string]string, len(file.OSAliases))
	for k, v := range file.OSAliases {
		aliases[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}

	seen := make(map[string]struct{}, len(file.Rules))
	compiled := make([]compiledRule, 0, len(file.Rules))
	for i, rule := range file.Rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		if err := validateRule(i, rule, seen); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("规则 %s: 正则无法编译: %w", rule.ID, err)
		}
		if err := checkGroup(rule, re.NumSubexp()); err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledRule{rule: rule, re: re})
	}
	if len(compiled) == 0 {
		return nil, fmt.Errorf("规则文件没有可用规则")
	}

	// 优先级高的先匹配。同一优先级保持文件中的先后顺序，方便规则作者控制兜底规则。
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].rule.Priority > compiled[j].rule.Priority
	})

	return &Engine{rules: compiled, aliases: aliases, source: path}, nil
}

func validateRule(index int, rule Rule, seen map[string]struct{}) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("第 %d 条规则缺少 id", index+1)
	}
	if _, ok := seen[rule.ID]; ok {
		return fmt.Errorf("规则 id 重复: %s", rule.ID)
	}
	seen[rule.ID] = struct{}{}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("规则 %s: 缺少 pattern", rule.ID)
	}
	if strings.TrimSpace(rule.Protocol) == "" {
		return fmt.Errorf("规则 %s: 缺少 protocol", rule.ID)
	}
	if math.IsNaN(rule.Confidence) || rule.Confidence < 0 || rule.Confidence > 1 {
		return fmt.Errorf("规则 %s: confidence 必须在 0 到 1 之间", rule.ID)
	}
	return nil
}

func checkGroup(rule Rule, n int) error {
	for _, g := range []struct {
		name string
		n    int
	}{
		{"product_group", rule.ProductGroup},
		{"version_group", rule.VersionGroup},
		{"os_hint_group", rule.OSHintGroup},
	} {
		if g.n < 0 || g.n > n {
			return fmt.Errorf("规则 %s: %s=%d 超出捕获组数量 %d", rule.ID, g.name, g.n, n)
		}
	}
	return nil
}

// Len 返回已启用规则数，供健康检查确认规则确实加载成功。
func (e *Engine) Len() int { return len(e.rules) }

// Source 返回规则文件路径，启动日志用它说明当前跑的是哪一份规则。
func (e *Engine) Source() string { return e.source }

// Identify 对一条 banner 做识别。任何异常输入都返回 Unknown，不向调用方抛错。
func (e *Engine) Identify(in Input) (res Result) {
	defer func() {
		if recover() != nil {
			res = Unknown(in)
		}
	}()
	if e == nil {
		return Unknown(in)
	}
	banner := normalizeBanner(in.Banner)
	banner = strings.TrimPrefix(banner, "\uFEFF")
	if len(banner) > maxBanner {
		banner = banner[:maxBanner]
	}
	if strings.Trim(banner, "\x00\r\n\t ") == "" {
		return Unknown(in)
	}
	for _, rule := range e.rules {
		m := rule.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		return e.apply(in, rule.rule, m)
	}
	return Unknown(in)
}

// IdentifyBatch 按输入顺序返回等长结果。单条即使内部异常也变成 unknown，不中断整批。
func (e *Engine) IdentifyBatch(items []Input) []Result {
	out := make([]Result, len(items))
	for i, item := range items {
		out[i] = e.Identify(item)
	}
	return out
}

func (e *Engine) apply(in Input, rule Rule, m []string) Result {
	product := strings.TrimSpace(rule.Product)
	if product == "" {
		product = group(m, rule.ProductGroup)
	}
	version := group(m, rule.VersionGroup)
	osHint := group(m, rule.OSHintGroup)
	if osHint == "" {
		osHint = strings.TrimSpace(rule.OSHint)
	}
	protocol := strings.TrimSpace(rule.Protocol)
	if protocol == "" {
		protocol = unknown
	}
	return Result{
		IP:         in.IP,
		Port:       in.Port,
		Protocol:   protocol,
		Product:    product,
		Version:    version,
		OSHint:     e.normalizeOS(osHint),
		Confidence: rule.Confidence,
	}
}

func (e *Engine) normalizeOS(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || e == nil {
		return s
	}
	if v, ok := e.aliases[strings.ToLower(s)]; ok {
		return v
	}
	return s
}

func group(m []string, n int) string {
	if n <= 0 || n >= len(m) {
		return ""
	}
	return strings.Trim(m[n], "\x00\r\n\t ")
}

// normalizeBanner 把扫描器导出的字面转义（\r、\n、\xNN、\u0000）还原成真实字节。
// JSON 里已经解码过的 banner 不含反斜杠，这里会原样返回。
func normalizeBanner(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'x':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 3
					continue
				}
			}
			b.WriteByte(s[i])
		case 'u':
			if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil && v <= 0xFF {
					b.WriteByte(byte(v))
					i += 5
					continue
				}
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
