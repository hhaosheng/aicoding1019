package engine_test

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aicoding1019/bannerd/internal/engine"
	"github.com/aicoding1019/bannerd/internal/rules"
)

func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	rs, err := rules.Load(rules.Options{})
	if err != nil {
		t.Fatalf("加载内置规则失败：%v", err)
	}
	return engine.New(rs)
}

func mustRead[T any](t *testing.T, path string) T {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败：%v", path, err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("解析 %s 失败：%v", path, err)
	}
	return v
}

func fp(f float64) string {
	// 避免 0.9 与 0.900000001 这类浮点噪声把断言写脆。
	return strings.TrimRight(strings.TrimRight(formatFloat(f), "0"), ".")
}

func formatFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// TestGoldenSample 是核心回归网：20 条自测输入的识别结果必须逐字段稳定。
//
// 黄金文件而不是内联断言，是为了让「调了权重/改了规则」的 diff 直接落在
// testdata/expected_20.json 上 —— 评审者能一眼看出识别行为变了什么。
func TestGoldenSample(t *testing.T) {
	eng := newEngine(t)
	items := mustRead[[]engine.Item](t, "../../testdata/sample_input.json")
	want := mustRead[[]engine.Result](t, "../../testdata/expected_20.json")

	if len(items) != len(want) {
		t.Fatalf("样例条数 %d 与期望条数 %d 不一致", len(items), len(want))
	}

	got := eng.FingerprintAll(items)
	for i := range want {
		if diff := compare(want[i], got[i]); diff != "" {
			t.Errorf("第 %d 条 (%s:%d) 不符：%s", i+1, want[i].IP, want[i].Port, diff)
		}
	}
}

func compare(want, got engine.Result) string {
	var parts []string
	if got.IP != want.IP {
		parts = append(parts, "ip "+want.IP+" -> "+got.IP)
	}
	if got.Port != want.Port {
		parts = append(parts, "port 不符")
	}
	if got.Protocol != want.Protocol {
		parts = append(parts, "protocol "+want.Protocol+" -> "+got.Protocol)
	}
	if got.Product != want.Product {
		parts = append(parts, "product "+want.Product+" -> "+got.Product)
	}
	if got.Version != want.Version {
		parts = append(parts, "version "+want.Version+" -> "+got.Version)
	}
	if got.OSHint != want.OSHint {
		parts = append(parts, "os_hint "+want.OSHint+" -> "+got.OSHint)
	}
	if math.Abs(got.Confidence-want.Confidence) > 1e-9 {
		parts = append(parts, "confidence "+fp(want.Confidence)+" -> "+fp(got.Confidence))
	}
	return strings.Join(parts, "; ")
}

// TestAcceptanceRows 把任务给的 7 行示例响应固化成断言。
//
// 与黄金文件的区别：黄金文件记录「当前行为」，这条测试记录「需求」。
// 前者可以随设计意图更新，后者不能 —— 它认的就是任务验收标准。
func TestAcceptanceRows(t *testing.T) {
	eng := newEngine(t)

	cases := []struct {
		item engine.Item
		want engine.Result
	}{
		{engine.Item{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			engine.Result{Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95}},
		{engine.Item{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			engine.Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.90}},
		{engine.Item{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
			engine.Result{Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.90}},
		{engine.Item{IP: "1.2.3.7", Port: 3306, Banner: `J\x00\x00\x00\n8.0.32\x00`},
			engine.Result{Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.90}},
		{engine.Item{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"},
			engine.Result{Protocol: "Redis", Product: "Redis", Confidence: 0.70}},
		{engine.Item{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			engine.Result{Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.90}},
		{engine.Item{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
			engine.Result{Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.85}},
	}

	for _, c := range cases {
		got := eng.Fingerprint(c.item)
		want := c.want
		want.IP, want.Port = c.item.IP, c.item.Port
		if diff := compare(want, got); diff != "" {
			t.Errorf("验收行 %s:%d 不符：%s", c.item.IP, c.item.Port, diff)
		}
	}
}

// TestUnknownIsNotAnError 对应任务硬要求：认不出来要正常返回一条 unknown 结果。
func TestUnknownIsNotAnError(t *testing.T) {
	eng := newEngine(t)

	cases := []struct {
		name string
		item engine.Item
	}{
		{"完全不认识", engine.Item{IP: "10.0.0.1", Port: 12345, Banner: "QUIT\r\n"}},
		{"空 banner", engine.Item{IP: "10.0.0.2", Port: 80}},
		{"纯二进制噪声", engine.Item{IP: "10.0.0.3", Port: 999, Banner: string([]byte{0xff, 0xfe, 0x00, 0x01, 0x02})}},
		{"非法 base64", engine.Item{IP: "10.0.0.4", Port: 80, BannerB64: "!!!!"}},
		{"超长重复文本", engine.Item{IP: "10.0.0.5", Port: 80, Banner: strings.Repeat("z", 200000)}},
		{"只有 NUL", engine.Item{IP: "10.0.0.6", Port: 7, Banner: "\x00\x00\x00"}},
		{"非法 UTF-8", engine.Item{IP: "10.0.0.7", Port: 80, Banner: string([]byte{0xc3, 0x28, 0xa0, 0xa1})}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := eng.Fingerprint(c.item) // 若 panic，这里就挂了
			if got.IP != c.item.IP || got.Port != c.item.Port {
				t.Fatalf("结果必须回填 ip/port，实际 %+v", got)
			}
			if got.Protocol == "" {
				t.Fatal("protocol 不允许为空，认不出来必须是 unknown")
			}
			if got.Confidence < 0 || got.Confidence > 1 {
				t.Fatalf("confidence 应在 0~1，实际 %v", got.Confidence)
			}
			if got.IsUnknown() && got.Confidence != 0 {
				t.Fatalf("unknown 的置信度应为 0，实际 %v", got.Confidence)
			}
		})
	}
}

// TestResultCountAlwaysMatchesInput：结果与输入严格 1:1 且顺序一致。
// 丢一条记录比返回 unknown 有害得多 —— 调用方无法区分「没识别出来」
// 和「根本没被处理」。
func TestResultCountAlwaysMatchesInput(t *testing.T) {
	eng := newEngine(t)
	items := []engine.Item{
		{IP: "a", Port: 1, Banner: "SSH-2.0-OpenSSH_9.3"},
		{IP: "b", Port: 2},
		{IP: "c", Port: 3, Banner: "\xff\xff\xff"},
		{IP: "d", Port: 4, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
	}
	got := eng.FingerprintAll(items)
	if len(got) != len(items) {
		t.Fatalf("结果条数 %d != 输入条数 %d", len(got), len(items))
	}
	for i := range items {
		if got[i].IP != items[i].IP || got[i].Port != items[i].Port {
			t.Fatalf("第 %d 条顺序错位：期望 %s:%d，实际 %s:%d",
				i, items[i].IP, items[i].Port, got[i].IP, got[i].Port)
		}
	}
}

// TestDeterministic 保证同一份输入永远得到同一份输出。
// 并发批量识别若按完成顺序回填，这条会随机挂。
func TestDeterministic(t *testing.T) {
	eng := newEngine(t)
	items := mustRead[[]engine.Item](t, "../../testdata/sample_input.json")

	// 超过并行阈值（64）才会走并发路径，所以先放大到 200 条。
	big := make([]engine.Item, 0, 200)
	for i := 0; i < 10; i++ {
		big = append(big, items...)
	}

	first := eng.FingerprintAll(big)
	for round := 0; round < 5; round++ {
		again := eng.FingerprintAll(big)
		for i := range first {
			if compare(first[i], again[i]) != "" {
				t.Fatalf("第 %d 轮第 %d 条结果漂移：%+v vs %+v", round, i, first[i], again[i])
			}
		}
	}
}

// TestConcurrentUseIsSafe：引擎声称并发安全，就得真的在 -race 下干净。
func TestConcurrentUseIsSafe(t *testing.T) {
	eng := newEngine(t)
	items := mustRead[[]engine.Item](t, "../../testdata/sample_input.json")
	want := eng.FingerprintAll(items)

	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for n := 0; n < 50; n++ {
				got := eng.FingerprintAll(items)
				for i := range want {
					if compare(want[i], got[i]) != "" {
						t.Errorf("并发下结果漂移：%+v vs %+v", want[i], got[i])
						return
					}
				}
			}
		}()
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}

// TestScoreModelMatchesPlan 用验收样例的置信度反推打分模型，逐项验算。
//
// 这组数字是「规则数据而非代码分支」在决定置信度的最好证明：
// 七个 0.90/0.95/0.85/0.70 全部只由 YAML 里的 score 与 os_hint 推出。
func TestScoreModelMatchesPlan(t *testing.T) {
	eng := newEngine(t)

	t.Run("SSH 全额加权到 ceiling", func(t *testing.T) {
		// 0.60 协议 + 0.15 产品 + 0.10 版本 + 0.05 OS + 0.05 端口相符 = 0.95
		got := eng.Fingerprint(engine.Item{IP: "x", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"})
		if got.Confidence != 0.95 {
			t.Fatalf("期望 0.95，实际 %.2f", got.Confidence)
		}
	})

	t.Run("端口相符才给 port_agree", func(t *testing.T) {
		on := eng.Fingerprint(engine.Item{IP: "x", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1"})
		// 2222 也在 ssh pack 的端口先验里，应与 22 同分 ——
		// 端口先验是「一组端口」而不是「一个端口」，否则改端口就得改规则。
		alt := eng.Fingerprint(engine.Item{IP: "x", Port: 2222, Banner: "SSH-2.0-OpenSSH_8.9p1"})
		if on.Confidence != alt.Confidence {
			t.Fatalf("同一端口先验集合内的端口应同分，实际 %.2f vs %.2f", on.Confidence, alt.Confidence)
		}

		odd := eng.Fingerprint(engine.Item{IP: "x", Port: 65000, Banner: "SSH-2.0-OpenSSH_8.9p1"})
		if d := on.Confidence - odd.Confidence; math.Abs(d-0.05) > 1e-9 {
			t.Fatalf("端口相符的权重应为 0.05，实际差 %.4f", d)
		}
	})

	t.Run("无版本时被 ceiling_no_version 压低", func(t *testing.T) {
		// Redis 只有产品没有版本：0.60+0.15+0.05 = 0.80，被 ceiling_no_version 0.70 压到 0.70
		got := eng.Fingerprint(engine.Item{IP: "x", Port: 6379, Banner: "+PONG"})
		if got.Product != "Redis" {
			t.Fatalf("应先识别出 Redis，实际 %q", got.Product)
		}
		if got.Version != "" {
			t.Fatalf("Redis inline reply 不该编出版本号，实际 %q", got.Version)
		}
		if got.Confidence != 0.70 {
			t.Fatalf("期望被无版本上限压到 0.70，实际 %.2f", got.Confidence)
		}
	})

	t.Run("规则级 ceiling 压低 Jetty", func(t *testing.T) {
		got := eng.Fingerprint(engine.Item{IP: "x", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"})
		if got.Product != "Jetty" {
			t.Fatalf("应先识别出 Jetty，实际 %q", got.Product)
		}
		if got.Confidence != 0.85 {
			t.Fatalf("Jetty 规则声明 ceiling 0.85，实际 %.2f", got.Confidence)
		}
	})

	t.Run("Jetty 的两种 Server 头写法都认", func(t *testing.T) {
		// 老式 Jetty 发 "Jetty/9.4.51"，现代 Jetty 默认发 "Jetty(11.0.24)"。
		// 两种写法必须落到同一个 product，版本号取分隔符后面那一段。
		// （这条是拿真实 banner 跑 demo 时发现漏网的：原正则只认斜杠形式。）
		for _, tc := range []struct{ banner, want string }{
			{"HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51", "9.4.51"},
			{"HTTP/1.1 200 OK\r\nServer: Jetty(11.0.24)", "11.0.24"},
			{"HTTP/1.1 200 OK\r\nServer: Jetty (12.0.15)", "12.0.15"},
			{"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)", "9.4.51.v20230217"},
		} {
			got := eng.Fingerprint(engine.Item{IP: "x", Port: 8080, Banner: tc.banner})
			if got.Product != "Jetty" || got.Version != tc.want {
				t.Errorf("%q -> product=%q version=%q，期望 Jetty/%s",
					tc.banner, got.Product, got.Version, tc.want)
			}
		}
	})

	t.Run("TLS 不给假版本号", func(t *testing.T) {
		// 03 01 是 record version（ClientHello 上的 legacy 值），不代表协商版本。
		// 宁可低分也不编一个版本出来。
		got := eng.Fingerprint(engine.Item{IP: "x", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"})
		if got.Protocol != "TLS" {
			t.Fatalf("应识别为 TLS，实际 %q", got.Protocol)
		}
		if got.Version != "" {
			t.Fatalf("TLS record 层不提供版本号，实际给出 %q", got.Version)
		}
		if got.Confidence != 0.60 {
			t.Fatalf("TLS 期望 0.60，实际 %.2f", got.Confidence)
		}
	})
}

// TestMatchAnySemantics 验证 match_any 是「任一命中」而不是「全部命中」。
func TestMatchAnySemantics(t *testing.T) {
	eng := newEngine(t)
	// Redis 的 inline reply 规则覆盖 +PONG / -ERR / -NOAUTH 等多种行首。
	for _, b := range []string{"+PONG", "-ERR unknown command", "-NOAUTH Authentication required."} {
		got := eng.Fingerprint(engine.Item{IP: "x", Port: 6379, Banner: b})
		if got.Protocol != "Redis" {
			t.Errorf("%q 应识别为 Redis，实际 %q", b, got.Protocol)
		}
	}
}

// TestDebugPayloadIsOptIn：不带 debug 时不得出现调试字段。
func TestDebugPayloadIsOptIn(t *testing.T) {
	eng := newEngine(t)
	it := engine.Item{IP: "x", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}

	if got := eng.Fingerprint(it); got.Debug != nil {
		t.Fatal("默认不该带 debug 负载")
	}
	got := eng.FingerprintOpt(it, true)
	if got.Debug == nil {
		t.Fatal("debug=true 时应带诊断负载")
	}
	if got.Debug.RuleID == "" {
		t.Fatal("debug 负载应包含命中的规则 id")
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(b) {
		t.Fatal("debug 响应必须是合法 UTF-8 JSON")
	}
	t.Logf("debug: %s", b)
}
