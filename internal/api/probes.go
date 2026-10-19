package api

import (
	"fmt"
	"time"

	"github.com/aicoding1019/bannerd/internal/engine"
)

// probeTTL 是自检结果的复用窗口。
//
// 取值 1s 的理由：docker healthcheck 的 interval 是 5s，必然每次都要现算
// （这正是我们想要的 —— 健康检查必须是当下的事实）；而同一秒内到达的
// 批量识别请求则共享同一份结果，不至于每个请求都重跑一遍探针。
const probeTTL = time.Second

// Probe 是一条自检探针：拿一段真实 banner 过一遍识别引擎，断言结果。
//
// 为什么把「健康检查」做成端到端自检，而不是回一句 {"status":"ok"}：
//
// 容器 healthy 的含义应该是「这个服务现在真的能干活」，而不是「进程还没死」。
// 一个 pid 活着、端口在听、但规则文件损坏导致所有识别都返回 unknown 的进程，
// 对调用方来说和挂了没有区别 —— 而它是不会让 http.Get("/health") 失败的。
//
// 探针刻意覆盖任务必答的每一个协议（SSH / HTTP / MySQL / Redis / FTP），
// 其中 MySQL 那条还顺带守住了「\x00 转义还原」这条最容易悄悄坏掉的链路：
// 一旦有人重构坏了 internal/banner 的 unescape，/health 立刻变 503。
var selfTestProbes = []Probe{
	{
		Name:     "ssh-openssh-ubuntu",
		Item:     engine.Item{IP: "127.0.0.1", Port: 22, Banner: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`},
		Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", MinConfidence: 0.95,
	},
	{
		Name:     "http-nginx",
		Item:     engine.Item{IP: "127.0.0.1", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
		Protocol: "HTTP", Product: "nginx", Version: "1.24.0", MinConfidence: 0.90,
	},
	{
		Name:     "http-apache-ubuntu",
		Item:     engine.Item{IP: "127.0.0.1", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"},
		Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", MinConfidence: 0.95,
	},
	{
		// 这条是整组探针里最重要的：它同时验证了
		// 「字面量 \x00 还原成 NUL」与「MySQL greeting 正则匹配到 8.0.32」。
		Name:     "mysql-greeting-escaped",
		Item:     engine.Item{IP: "127.0.0.1", Port: 3306, Banner: `J\x00\x00\x00\n8.0.32\x00`},
		Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", MinConfidence: 0.90,
	},
	{
		Name:     "redis-error-reply",
		Item:     engine.Item{IP: "127.0.0.1", Port: 6379, Banner: `-ERR wrong number of arguments for 'get' command`},
		Protocol: "Redis", Product: "Redis", MinConfidence: 0.70,
	},
	{
		Name:     "ftp-proftpd",
		Item:     engine.Item{IP: "127.0.0.1", Port: 21, Banner: `220 ProFTPD 1.3.7 Server (ProFTPD)`},
		Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", MinConfidence: 0.90,
	},
}

// Probe 是一条自检探针的期望值。
type Probe struct {
	Name string
	Item engine.Item

	Protocol string
	Product  string
	Version  string
	OSHint   string

	// MinConfidence 是期望的最低置信度；0 表示不检查。
	// 用下限而不是精确值：调权重不该让健康检查变红，
	// 但「识别彻底坏掉」必须让它变红。
	MinConfidence float64
}

// ProbeResult 是一条探针的执行结果。
type ProbeResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Got    string `json:"got,omitempty"`
	Want   string `json:"want,omitempty"`
}

// Probes 返回全部探针（副本），供测试复用。
func Probes() []Probe {
	out := make([]Probe, len(selfTestProbes))
	copy(out, selfTestProbes)
	return out
}

// RunProbes 用给定引擎跑一遍全部探针。
//
// 每次 /health 都真跑：6 条记录 × 几十条规则的代价在微秒~毫秒量级，
// 相比它带来的「服务确实还能识别」这一保证，完全不值一提。
func RunProbes(eng *engine.Engine) []ProbeResult {
	out := make([]ProbeResult, 0, len(selfTestProbes))
	for _, p := range selfTestProbes {
		out = append(out, runProbe(eng, p))
	}
	return out
}

func runProbe(eng *engine.Engine, p Probe) ProbeResult {
	got := eng.Fingerprint(p.Item)
	res := ProbeResult{
		Name:   p.Name,
		Passed: true,
		Got:    fmt.Sprintf("%s/%s/%s/%s/%.2f", got.Protocol, got.Product, got.Version, got.OSHint, got.Confidence),
		Want:   fmt.Sprintf("%s/%s/%s/%s/>=%.2f", p.Protocol, p.Product, p.Version, p.OSHint, p.MinConfidence),
	}

	// 期望为空的字段一律不比对：探针只对「必须成立」的部分断言，
	// 避免把无关紧要的措辞变化变成线上告警。
	if p.Protocol != "" && got.Protocol != p.Protocol {
		res.Passed = false
	}
	if p.Product != "" && got.Product != p.Product {
		res.Passed = false
	}
	if p.Version != "" && got.Version != p.Version {
		res.Passed = false
	}
	if p.OSHint != "" && got.OSHint != p.OSHint {
		res.Passed = false
	}
	if p.MinConfidence > 0 && got.Confidence+1e-9 < p.MinConfidence {
		res.Passed = false
	}
	return res
}

// probeState 返回最近一次自检结果，probeTTL 内复用。
//
// /health 与 /fingerprint 都走这一个入口，于是「服务还能不能正确识别」
// 全局只有一个判断来源 —— 不会出现健康检查说 OK、而识别结果其实全错的情形。
func (s *Server) probeState() []ProbeResult {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()

	if s.probeRes != nil && time.Since(s.probeAt) < probeTTL {
		return s.probeRes
	}
	s.probeRes = RunProbes(s.eng)
	s.probeAt = time.Now()
	return s.probeRes
}

// failedProbes 数出没通过的探针条数。
func failedProbes(probes []ProbeResult) int {
	n := 0
	for _, p := range probes {
		if !p.Passed {
			n++
		}
	}
	return n
}
