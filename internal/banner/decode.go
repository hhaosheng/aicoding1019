// Package banner 把「扫描器吐出来的原始 banner」还原成可以稳定匹配的形态。
//
// 这个包存在的原因只有一个：真实扫描数据里的 banner 是**字面量转义文本**，
// 而任务给的样例正是这个形态：
//
//	"J\x00\x00\x00\n8.0.32\x00"
//
// 这串东西从 JSON 解析出来之后，是一个 4 字符的序列 `\` `x` `0` `0`，
// 而不是 NUL 字节。任何直接把 banner 当字符串去匹配的正则都会扑空。
// 同时，它在线路上真正的样子（见 plan.md §3.2）是：
//
//	0a 38 2e 30 2e 33 32 00   // 4 字节长度 + 序列号 + 0x0A + "8.0.32" + NUL
//
// 所以本包做三件事：
//  1. 还原转义（\xNN、\n、\r、\t、\0…）得到 Text；
//  2. 把任意字节串按 Latin-1 逐字节映射成**字节精确**的匹配形态 Match，
//     这样「一个字符 == 一个字节」恒成立，正则里的 \x00 就能真的匹配到 NUL，
//     而不会像 UTF-8 那样把一个非法字节变成 U+FFFD 把匹配毁掉；
//  3. 同时保留未还原的原始形态 Alt，让引擎可以「匹配不上再退化到原始文本」
//     地做第二遍匹配（双模匹配）。
package banner

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// MaxMatchBytes 限制单个 banner 参与匹配的字节数。
//
// 这是纯防御：真实 banner 最长也就几 KB，而恶意/损坏的输入可以塞到几十 MB，
// 让「正则跑 O(n) 遍 × 规则数」变成拒绝服务。超出部分直接截断 ——
// 截断只可能让置信度变低，不可能让服务崩掉。
const MaxMatchBytes = 64 << 10 // 64 KiB

// FormName 标识一个匹配形态，出现在 debug 输出里，方便排查「为什么这条没认出来」。
type FormName string

const (
	FormCanonical FormName = "canonical" // 转义还原后的字节精确形态
	FormRaw       FormName = "raw"       // 原样文本（未还原转义）
)

// Form 是一个可参与匹配的 (名称, 数据) 对。
type Form struct {
	Name FormName
	Data string
}

// Decoded 是同一个 banner 的多种等价形态。
type Decoded struct {
	// Raw 是收到的原文，未做任何处理（debug 及第二遍匹配用）。
	Raw string
	// Text 是转义还原后的形态。
	Text string
	// Match 是字节精确的匹配形态（Latin-1 逐字节映射），限长 MaxMatchBytes。
	Match string
	// Alt 是「与 Match 不同」的退化匹配形态：未还原转义的原文。
	// 为空表示无需第二遍匹配。
	Alt string
	// Safe 是 UTF-8 合法形态，仅用于日志与人类可读输出 —— 绝不参与匹配。
	Safe string

	// 以下为诊断信息，只在 ?debug=1 时对外暴露。
	HadEscapes  bool // 原文含 \xNN / \n 之类转义序列
	HadNUL      bool // 还原后含 NUL 字节（二进制协议强信号）
	Binary      bool // 含不可打印字节，判定为二进制 banner
	InvalidUTF8 bool // 原文不是合法 UTF-8
	Truncated   bool // 超过 MaxMatchBytes 被截断
	Len         int  // 处理前的原始字节数
}

// MatchForms 返回应当参与匹配的形态列表，按优先级从高到低。
//
// 顺序即语义：canonical 优先；只有当 canonical 一遍什么都没匹配上时，
// 引擎才会退到 raw 再试一遍（见 internal/engine）。
func (d Decoded) MatchForms() []Form {
	out := make([]Form, 0, 2)
	out = append(out, Form{Name: FormCanonical, Data: d.Match})
	if d.Alt != "" {
		out = append(out, Form{Name: FormRaw, Data: d.Alt})
	}
	return out
}

// Decode 处理字符串形态的 banner。
func Decode(raw string) Decoded { return DecodeBytes([]byte(raw)) }

// DecodeBytes 处理字节形态的 banner。
func DecodeBytes(raw []byte) Decoded {
	d := Decoded{Raw: string(raw), Len: len(raw)}
	if d.Len > MaxMatchBytes {
		raw = raw[:MaxMatchBytes]
		d.Truncated = true
	}

	d.Text = unescape(d.Raw)
	d.HadEscapes = d.Text != d.Raw

	d.InvalidUTF8 = !utf8.ValidString(d.Raw)
	d.Safe = strings.ToValidUTF8(d.Text, "\uFFFD")
	d.HadNUL = strings.IndexByte(d.Text, 0x00) >= 0
	d.Binary = hasControlBytes(d.Text)

	d.Match = latin1(d.Text)
	if d.Raw != d.Text {
		d.Alt = latin1(d.Raw)
	}
	// 截断保护同样作用在匹配形态上：latin1 会把 1 字节膨胀成最多 2 字节。
	if len(d.Match) > MaxMatchBytes {
		d.Match = d.Match[:MaxMatchBytes]
	}
	return d
}

// Input 从请求里挑出真正的 banner 字节。
//
// banner 与 banner_b64 同时给出时以 banner_b64 为准（它无损，且不会踩 JSON 转义），
// 但两者都为空不算错误 —— 那只是「这条数据没采到 banner」，照样要返回一条结果。
func Input(text, b64 string) ([]byte, error) {
	if b64 != "" {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			// 尝试 URL-safe 与无填充变体，提升对上游扫描器的宽容度。
			if b2, err2 := base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "=")); err2 == nil {
				return b2, nil
			}
			return nil, err
		}
		return b, nil
	}
	return []byte(text), nil
}

// unescape 把扫描数据里的**字面量转义序列**还原成真字节。
//
// 只处理明确无歧义的序列：
//
//	\xNN  -> 单字节             \\  -> 单个反斜杠
//	\r \n \t \0 \a \b \f \v -> 对应控制字节
//
// 遇到不认识的 \X 时原样保留两个字符 —— 宁可少还原，也不要把
// "C:\path" 这类内容吃掉。因为保留了原始形态 Alt，猜错也不会导致漏识别。
func unescape(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch n := s[i+1]; n {
		case 'x':
			if i+3 < len(s) {
				if hi, ok1 := fromHex(s[i+2]); ok1 {
					if lo, ok2 := fromHex(s[i+3]); ok2 {
						b.WriteByte(hi<<4 | lo)
						i += 3
						continue
					}
				}
			}
			b.WriteByte(c)
		case '\\':
			b.WriteByte('\\')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case '0':
			b.WriteByte(0x00)
			i++
		case 'a':
			b.WriteByte(0x07)
			i++
		case 'b':
			b.WriteByte(0x08)
			i++
		case 'f':
			b.WriteByte(0x0C)
			i++
		case 'v':
			b.WriteByte(0x0B)
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// latin1 把字节串规范成「一个 rune 恰对应一个线路字节」的形态。
//
// 这是本包最关键的一步。Go 的正则工作在 rune 上：若拿一个含 0x80 以上字节的
// 非法 UTF-8 串去匹配，那些字节会先被替换成 U+FFFD，匹配结果就开始骗人了。
// 规范成「rune 值 == 字节值」之后，规则里写 \x00 就真能匹配到 NUL，
// 匹配偏移量也能直接换算成字节偏移。
//
// 关键在于**只转化真正非法的字节**，不能无脑逐字节重映射：
// 同一个线路字节会以两种形态进来，而它们必须收敛到同一个 rune 序列，
// 否则「换个 JSON 写法就识别不出来」——
//
//	形态 A：JSON \u00a5      -> Go 串里是合法 UTF-8 的 C2 A5，rune U+00A5
//	形态 B：字面量 \xa5 还原 -> Go 串里是裸字节 A5，非法 UTF-8
//
// 对 A 必须原样保留（它已经是 rune U+00A5 了，再逐字节重映射会变成
// rune U+00C2 + U+00A5 两个 rune，把 TLS record 的定长字段撑开、匹配失败）；
// 对 B 才需要把那个非法字节提升成 rune U+00A5。两种形态于是得到同一个结果。
//
// 纯 ASCII（绝大多数 HTTP/FTP/SSH banner）走快速路径，零分配。
func latin1(s string) string {
	if isASCII(s) {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			// 非法 UTF-8 字节：按 Latin-1 语义把它当作 U+00XX。
			b = utf8.AppendRune(b, rune(s[i]))
			i++
			continue
		}
		b = append(b, s[i:i+size]...)
		i += size
	}
	return string(b)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// hasControlBytes 判断是否含不可打印控制字节（排除 \t \n \r 这些文本协议常用的）。
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
		if c == 0x7F {
			return true
		}
	}
	return false
}
