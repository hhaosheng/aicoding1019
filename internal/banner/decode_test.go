package banner

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRepairJSONEscapes 锁死「整份文件不该被一条脏数据带崩」这条要求。
//
// 任务样例里的 MySQL banner 写作 "J\x00\x00\x00\n8.0.32\x00"，
// 而 \x 不是合法 JSON 转义 —— 严格解析器会把**整个数组**判为非法。
func TestRepairJSONEscapes(t *testing.T) {
	const bad = `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`

	// 先确认它真的不是合法 JSON：否则这条测试就是自欺欺人。
	var probe []map[string]any
	if err := json.Unmarshal([]byte(bad), &probe); err == nil {
		t.Fatal("前置假设失败：这份输入本应是非法 JSON")
	}

	repaired := RepairJSONEscapes([]byte(bad))
	if string(repaired) == bad {
		t.Fatal("RepairJSONEscapes 没有改动任何内容")
	}
	var got []map[string]any
	if err := json.Unmarshal(repaired, &got); err != nil {
		t.Fatalf("修补后仍无法解析：%v\n修补结果：%s", err, repaired)
	}

	bannerText := got[0]["banner"].(string)
	// 修补只负责让 JSON 层通过；还原成真字节是 Decode 的职责。
	if d := Decode(bannerText); d.HadEscapes != true {
		t.Fatalf("修补后的文本应仍带转义序列，实际 %q", bannerText)
	} else if !d.HadNUL {
		t.Fatalf("还原后应含 NUL 字节，实际 %q", d.Text)
	}
}

// TestRepairJSONEscapesKeepsValidEscapes 保证修补器不会把合法转义改坏。
func TestRepairJSONEscapesKeepsValidEscapes(t *testing.T) {
	const good = `{"a":"line1\r\nline2","b":"quote\"end","c":"back\\slash","d":"\u00e9","e":"\u0041"}`
	out := RepairJSONEscapes([]byte(good))
	if string(out) != good {
		t.Fatalf("合法 JSON 不该被改动\n 原: %s\n 后: %s", good, out)
	}
}

// TestMatchFormsConvergeOnSameWireBytes 是一次真实踩坑的回归测试。
//
// 同一个线路字节 0xA5 会以两种形态进来：
//
//	形态 A：JSON \u00a5      -> Go 串里是合法 UTF-8 的 C2 A5，解码为 rune U+00A5
//	形态 B：字面量 \xa5 还原 -> Go 串里是裸字节 A5，非法 UTF-8
//
// 早先的 latin1 无条件逐字节重映射：对 A 会把 C2 和 A5 各当作一个字节，
// 变成 rune U+00C2 + U+00A5 **两个** rune，于是 TLS record 头的定长字段
// 整体后移，ClientHello 规则静默失配（置信度从 0.60 掉到 0.55）。
// 两种写法给出的必须是同一份字节，否则「换个 JSON 编码就识别不出来」。
func TestMatchFormsConvergeOnSameWireBytes(t *testing.T) {
	const (
		asJSONEscapes = `"\u0016\u0003\u0001\u0000\u00a5\u0001\u0000\u0000\u00a1"`
		asLiteralHex  = `"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"`
	)

	var fromJSON string
	if err := json.Unmarshal([]byte(asJSONEscapes), &fromJSON); err != nil {
		t.Fatalf("形态 A 解析失败：%v", err)
	}

	var fromLiteral string
	if err := json.Unmarshal(RepairJSONEscapes([]byte(asLiteralHex)), &fromLiteral); err != nil {
		t.Fatalf("形态 B 解析失败：%v", err)
	}

	a, b := Decode(fromJSON), Decode(fromLiteral)

	if a.Match != b.Match {
		t.Fatalf("两种形态归一化后不一致\n A(JSON转义): % x\n B(字面量)  : % x", a.Match, b.Match)
	}
	// 线路字节数 == rune 数：这正是「一个 rune 恰对应一个字节」的含义。
	if n := utf8.RuneCountInString(a.Match); n != 9 {
		t.Fatalf("归一化后应有 9 个 rune（对应 9 个线路字节），实际 %d：% x", n, a.Match)
	}
	if a.HadNUL != true || b.HadNUL != true {
		t.Fatalf("两种形态都应含 NUL：A=%v B=%v", a.HadNUL, b.HadNUL)
	}
}

// TestLatin1LeavesValidMultibyteIntact 保证真正的多字节文本不被拆散。
func TestLatin1LeavesValidMultibyteIntact(t *testing.T) {
	const s = "Server: nginx/1.24.0（测试）"
	if got := latin1(s); got != s {
		t.Fatalf("合法 UTF-8 被改动了\n 原: %q\n 后: %q", s, got)
	}
}

// TestLatin1IsIdempotent：规范化一次与两次结果必须相同，否则双遍匹配会自相矛盾。
func TestLatin1IsIdempotent(t *testing.T) {
	raw := string([]byte{0x16, 0x03, 0x01, 0x00, 0xa5, 0xff, 0x00, 'x'})
	once := latin1(raw)
	if twice := latin1(once); twice != once {
		t.Fatalf("latin1 不是幂等的\n 一次: % x\n 两次: % x", once, twice)
	}
}

func TestUnescape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"NUL 转义", `J\x00\x00\x00\n8.0.32\x00`, "J\x00\x00\x00\n8.0.32\x00"},
		{"CRLF", `a\r\nb`, "a\r\nb"},
		{"双反斜杠", `C:\\path`, `C:\path`},
		{"未知转义原样保留", `C:\Users\me`, `C:\Users\me`},
		{"截断的十六进制不吞字符", `ab\x0`, `ab\x0`},
		{"无反斜杠走快路径", "plain banner", "plain banner"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := unescape(c.in); got != c.want {
				t.Fatalf("unescape(%q) = %q，期望 %q", c.in, got, c.want)
			}
		})
	}
}

// TestDecodeAltOnlyWhenNeeded：没有转义时不该白白多跑一遍匹配。
func TestDecodeAltOnlyWhenNeeded(t *testing.T) {
	if d := Decode("HTTP/1.1 200 OK"); d.Alt != "" {
		t.Fatalf("无转义输入不该产生 Alt，实际 %q", d.Alt)
	}
	d := Decode(`J\x00\x00\x00\n8.0.32\x00`)
	if d.Alt == "" {
		t.Fatal("含转义输入应产生 Alt，供双遍匹配兜底")
	}
	if len(d.MatchForms()) != 2 {
		t.Fatalf("应有两个匹配形态，实际 %d", len(d.MatchForms()))
	}
}

// TestDecodeTruncatesHugeBanner：截断保护必须生效，且不能让服务出错。
func TestDecodeTruncatesHugeBanner(t *testing.T) {
	huge := strings.Repeat("A", MaxMatchBytes*3)
	d := Decode(huge)
	if !d.Truncated {
		t.Fatal("超长输入未被标记为截断")
	}
	if len(d.Match) > MaxMatchBytes {
		t.Fatalf("Match 长度 %d 超过上限 %d", len(d.Match), MaxMatchBytes)
	}
	if d.Len != len(huge) {
		t.Fatalf("Len 应记录原始长度 %d，实际 %d", len(huge), d.Len)
	}
}

func TestInputPrefersB64(t *testing.T) {
	// "J\x00\x00\x00\n8.0.32\x00" 的 base64
	const b64 = "SgAAAAo4LjAuMzIA"
	got, err := Input("this text is ignored", b64)
	if err != nil {
		t.Fatalf("base64 解码失败：%v", err)
	}
	if string(got) != "J\x00\x00\x00\n8.0.32\x00" {
		t.Fatalf("banner_b64 未被优先采用：% x", got)
	}

	// 非法 base64 返回错误而不是 panic —— 调用方据此降级为 unknown。
	if _, err := Input("", "!!!not base64!!!"); err == nil {
		t.Fatal("非法 base64 应返回错误")
	}
	// 两者都为空不是错误。
	if b, err := Input("", ""); err != nil || len(b) != 0 {
		t.Fatalf("空输入应返回空字节且无错误，实际 %q %v", b, err)
	}
}
