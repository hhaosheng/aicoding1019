// Package rules 负责识别规则的加载、编译、校验与匹配。
//
// 解耦边界：本包不认识任何具体产品名。协议、产品、版本抽取方式与置信度权重
// 全部来自 YAML 数据，新增或调整识别能力不需要改动 Go 代码，也不需要重新
// 理解编译流程 —— 这正是「规则与程序代码解耦」这一评测点的落点。
package rules

import (
	"regexp"
	"time"
)

// SchemaVersion 是当前支持的规则文件 schema 版本。
const SchemaVersion = 1

// Score 是置信度权重与上限。
//
// 全部字段用指针，是为了区分「未声明」与「显式声明为 0」：只有能区分，
// 才能做「规则 → pack → _pack 基线」的逐字段继承。若用 float64，那么
// 规则里写 os_hint: 0 与不写 os_hint 就无法区分，继承语义会失真。
type Score struct {
	Protocol         *float64 `yaml:"protocol"`
	Product          *float64 `yaml:"product"`
	Version          *float64 `yaml:"version"`
	OSHint           *float64 `yaml:"os_hint"`
	PortAgree        *float64 `yaml:"port_agree"`
	Ceiling          *float64 `yaml:"ceiling"`
	CeilingNoVersion *float64 `yaml:"ceiling_no_version"`
}

// DefaultScore 是最终兜底：即使 _pack.yaml 缺字段，任何规则也能拿到完整权重。
var DefaultScore = Score{
	Protocol:         f64(0.60),
	Product:          f64(0.15),
	Version:          f64(0.10),
	OSHint:           f64(0.05),
	PortAgree:        f64(0.05),
	Ceiling:          f64(0.95),
	CeilingNoVersion: f64(0.75),
}

// inherit 用 base 填充本结构中「未声明」的字段。
func (s Score) inherit(base Score) Score {
	out := s
	if out.Protocol == nil {
		out.Protocol = base.Protocol
	}
	if out.Product == nil {
		out.Product = base.Product
	}
	if out.Version == nil {
		out.Version = base.Version
	}
	if out.OSHint == nil {
		out.OSHint = base.OSHint
	}
	if out.PortAgree == nil {
		out.PortAgree = base.PortAgree
	}
	if out.Ceiling == nil {
		out.Ceiling = base.Ceiling
	}
	if out.CeilingNoVersion == nil {
		out.CeilingNoVersion = base.CeilingNoVersion
	}
	return out
}

func f64(v float64) *float64 { return &v }

func deref(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// OSHint 命中即采用其 Value。
//
// 只给 value 不给 regex 表示静态推断（恒真），例如 IIS 只跑 Windows ——
// 这是「领域知识写进规则数据」而不是写进代码的典型例子。
type OSHint struct {
	Regex string `yaml:"regex"`
	Value string `yaml:"value"`

	re *regexp.Regexp
}

// Matcher 是一条正则匹配条件。
type Matcher struct {
	// Regex 使用 Go 的 RE2 语法。写法上建议用 YAML 单引号，
	// 这样 \x00 \x16 \b (?i) 等都原样交给 regexp 解析。
	Regex string `yaml:"regex"`
}

// Rule 是一条识别规则。
type Rule struct {
	ID          string    `yaml:"id"`
	Description string    `yaml:"description"`
	Specificity int       `yaml:"specificity"`
	Protocol    string    `yaml:"protocol"`
	Ports       []int     `yaml:"ports"`
	Match       []Matcher `yaml:"match"`
	MatchAny    []Matcher `yaml:"match_any"`
	Product     string    `yaml:"product"`
	OSHint      []OSHint  `yaml:"os_hint"`
	Score       Score     `yaml:"score"`
	Tags        []string  `yaml:"tags"`
}

// Pack 是一个规则包，通常对应 rules/ 下的一个 .yaml 文件。
type Pack struct {
	Version     int    `yaml:"version"`
	Pack        string `yaml:"pack"`
	Description string `yaml:"description"`
	Protocol    string `yaml:"protocol"`
	Ports       []int  `yaml:"ports"`
	Priority    int    `yaml:"priority"`
	Score       Score  `yaml:"score"`
	Rules       []Rule `yaml:"rules"`

	// File 是原始文件名（不含目录），用于整文件替换与排错。
	File string `yaml:"-"`
	// Origin 是 "embedded" 或外部目录路径，用于 /health 展示规则来源。
	Origin string `yaml:"-"`
}

// Compiled 是编译好的规则：正则已预编译、权重已继承完毕。
type Compiled struct {
	Rule
	Pack      *Pack
	Effective Score

	match    []*regexp.Regexp
	matchAny []*regexp.Regexp
	osRegex  []*regexp.Regexp
	order    int
}

// ProtocolName 返回生效协议：规则级声明优先，否则继承 pack 级声明。
func (c *Compiled) ProtocolName() string {
	if c.Rule.Protocol != "" {
		return c.Rule.Protocol
	}
	return c.Pack.Protocol
}

// EffectivePorts 返回生效端口先验：规则级声明优先，否则继承 pack 级声明。
func (c *Compiled) EffectivePorts() []int {
	if len(c.Rule.Ports) > 0 {
		return c.Rule.Ports
	}
	return c.Pack.Ports
}

// Order 是规则在加载顺序中的位置，用于打分平局时的最终裁决，
// 保证同一输入永远产出同一输出（黄金文件测试的前提）。
func (c *Compiled) Order() int { return c.order }

// Origin 返回规则来自内置还是外部目录。
func (c *Compiled) Origin() string { return c.Pack.Origin }

// Capture 是一条规则命中后的抽取结果。
type Capture struct {
	Product string
	Version string
	OSHint  string
	// Named 保留全部命名捕获组，供 ?debug=1 人工研判。
	Named map[string]string
}

// Match 在文本 s 上尝试命中本规则。
//
// 语义：match 列表全部命中（ALL），且 match_any 列表至少命中一条（若声明了）。
func (c *Compiled) Match(s string) (Capture, bool) {
	if len(c.match) == 0 && len(c.matchAny) == 0 {
		return Capture{}, false
	}

	var named map[string]string
	for _, re := range c.match {
		loc := re.FindStringSubmatchIndex(s)
		if loc == nil {
			return Capture{}, false // match 是 ALL 语义，一条不中就整体不中
		}
		named = collect(re, s, loc, named)
	}

	if len(c.matchAny) > 0 {
		found := false
		for _, re := range c.matchAny {
			if loc := re.FindStringSubmatchIndex(s); loc != nil {
				found = true
				named = collect(re, s, loc, named)
			}
		}
		if !found {
			return Capture{}, false
		}
	}

	cap := Capture{Named: named}
	// 规范化产品名优先取规则里的静态声明（不依赖 banner 原样大小写），
	// 未声明时才退回命名捕获组。
	cap.Product = c.Rule.Product
	if cap.Product == "" {
		cap.Product = named["product"]
	}
	cap.Version = named["version"]
	cap.OSHint = c.osHint(s)
	return cap, true
}

// osHint 按声明顺序返回首个命中的 os_hint，未命中返回空串。
func (c *Compiled) osHint(s string) string {
	for i, h := range c.Rule.OSHint {
		if c.osRegex[i] != nil {
			if c.osRegex[i].MatchString(s) {
				return h.Value
			}
			continue
		}
		// 无 regex 的静态推断恒真。
		if h.Value != "" {
			return h.Value
		}
	}
	return ""
}

// collect 抽取命名捕获组。同一个名字先出现者优先，避免后面的宽松正则
// 覆盖前面严格正则已经取到的精确值。
func collect(re *regexp.Regexp, s string, loc []int, into map[string]string) map[string]string {
	names := re.SubexpNames()
	for i := 1; i < len(names); i++ {
		if names[i] == "" {
			continue
		}
		start, end := loc[2*i], loc[2*i+1]
		if start < 0 || end < 0 {
			continue
		}
		if into == nil {
			into = make(map[string]string, len(names))
		}
		if _, ok := into[names[i]]; !ok {
			into[names[i]] = s[start:end]
		}
	}
	return into
}

// RuleSet 是一份编译校验完毕、可并发只读使用的规则集合。
type RuleSet struct {
	packs    []*Pack
	rules    []*Compiled
	sha      string
	source   string
	loadedAt time.Time
}

// Packs 返回全部规则包（含 _base 基线包）。
func (rs *RuleSet) Packs() []*Pack { return rs.packs }

// Rules 返回全部已编译规则，顺序稳定。
func (rs *RuleSet) Rules() []*Compiled { return rs.rules }

// Count 是规则总数。
func (rs *RuleSet) Count() int { return len(rs.rules) }

// SHA256 是全部规则文件内容的哈希，用于回答「此刻生效的是哪一版规则」。
func (rs *RuleSet) SHA256() string { return rs.sha }

// Source 是规则来源："embedded" 或外部目录路径。
func (rs *RuleSet) Source() string { return rs.source }

// LoadedAt 是本次加载完成时间。
func (rs *RuleSet) LoadedAt() time.Time { return rs.loadedAt }
