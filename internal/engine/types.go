// Package engine 把「banner 解码」与「规则匹配」串成一条识别流水线，
// 并按 plan.md §4.2 的模型给出置信度。
//
// 本包是整个系统里唯一允许出现「打分」二字的地方：规则文件只说
// 「命中我意味着什么」，引擎说「这值多少分」。两者的分界线就是
// 规则与代码的解耦边界。
package engine

// UnknownProtocol 是「认不出来」的统一表示。
//
// 刻意不是空串、也不是错误：任务要求认不出来要能正常返回一条结果，
// 而不是报错或从数组里消失 —— 丢失一条记录比返回 unknown 有害得多，
// 因为调用方无法区分「这条没识别出来」和「这条根本没被处理」。
const UnknownProtocol = "unknown"

// Item 是一条待识别的扫描原始记录。
type Item struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`

	// Banner 是文本形态的 banner。真实扫描数据里它常含字面量转义
	// （`\x00`、`\r\n`），由 internal/banner 负责还原。
	Banner string `json:"banner,omitempty"`

	// BannerB64 是二进制 banner 的无损载体。与 Banner 同时给出时以本字段为准。
	BannerB64 string `json:"banner_b64,omitempty"`
}

// Result 是一条识别结果。字段名与任务要求逐一对应，不多不少。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`

	// Debug 仅在请求带 ?debug=1 时填充，正常响应里不出现。
	Debug *Debug `json:"debug,omitempty"`
}

// Unknown 构造一条「认不出来」的结果。
func Unknown(ip string, port int) Result {
	return Result{IP: ip, Port: port, Protocol: UnknownProtocol}
}

// IsUnknown 判断是否未识别出协议。
func (r Result) IsUnknown() bool { return r.Protocol == "" || r.Protocol == UnknownProtocol }

// Debug 是 ?debug=1 时的诊断负载。
//
// 之所以要做这个开关：指纹识别最常见的求助是「这条为什么认不出来」。
// 没有候选列表时只能靠猜；有了它，看到的就是事实 ——
// 是规则没命中（Candidates 为空），还是命中了但被更高分的规则压过。
type Debug struct {
	RuleID string            `json:"rule_id,omitempty"`
	Pack   string            `json:"pack,omitempty"`
	Form   string            `json:"matched_form,omitempty"`
	Named  map[string]string `json:"named,omitempty"`
	Note   string            `json:"note,omitempty"`

	Candidates []Candidate `json:"candidates,omitempty"`

	BannerLen  int  `json:"banner_len"`
	HadEscapes bool `json:"had_escapes,omitempty"`
	HadNUL     bool `json:"had_nul,omitempty"`
	Binary     bool `json:"binary,omitempty"`
	Truncated  bool `json:"truncated,omitempty"`
	Recovered  bool `json:"recovered,omitempty"`
}

// Candidate 是一条命中规则及其得分，用于人工研判。
type Candidate struct {
	RuleID      string  `json:"rule_id"`
	Pack        string  `json:"pack"`
	Protocol    string  `json:"protocol"`
	Product     string  `json:"product,omitempty"`
	Version     string  `json:"version,omitempty"`
	OSHint      string  `json:"os_hint,omitempty"`
	Confidence  float64 `json:"confidence"`
	Specificity int     `json:"specificity"`
	Form        string  `json:"form"`
}
