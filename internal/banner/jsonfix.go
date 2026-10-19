package banner

// RepairJSONEscapes 让「含非法 JSON 转义」的输入也能被解析。
//
// 为什么不直接用 encoding/json：
//
//	{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}
//
// 这份数据里 \x 不是合法的 JSON 转义序列，标准解析器会直接报
// "invalid character 'x' in string escape code" 并把**整份文件**判为错误。
// 于是一条脏数据就能让整批 20 条全丢 —— 这正好踩中任务要求里的
// 「不允许因为认不出来就报错崩掉」。
//
// 这里的策略是「修补而不是拒绝」：把不合法的 `\X` 改写成 `\\X`，
// 让它在 JSON 层退化成两个普通字符（反斜杠 + X），
// 随后由 Decode 的 unescape 还原成真字节。信息一点没丢。
//
// 注意：合法转义一个都不动，特别是 `\\`（字面量反斜杠）——
// 它必须留下，否则 "C:\\path" 会被误伤。
//
// 输入若本来就是合法 JSON，输出与输入逐字节相同。
func RepairJSONEscapes(in []byte) []byte {
	// 常见情况下没有任何需要修补的地方，直接复用原切片。
	idx := firstSuspectEscape(in)
	if idx < 0 {
		return in
	}

	out := make([]byte, 0, len(in)+8)
	out = append(out, in[:idx]...)

	for i := idx; i < len(in); i++ {
		c := in[i]
		if c != '\\' || i+1 >= len(in) {
			out = append(out, c)
			continue
		}
		switch n := in[i+1]; {
		case n == '"', n == '\\', n == '/', n == 'b', n == 'f', n == 'n', n == 'r', n == 't':
			// 标准单字符转义，原样保留。
			out = append(out, c, n)
			i++
		case n == 'u':
			if i+5 < len(in) && isHex4(in[i+2:i+6]) {
				out = append(out, in[i:i+6]...)
				i += 5
				continue
			}
			// \u 后面不是 4 位十六进制：当作字面量反斜杠处理。
			out = append(out, '\\', '\\', n)
			i++
		default:
			// \x、\0 之类：把反斜杠转义掉，退化为字面量文本。
			out = append(out, '\\', '\\', n)
			i++
		}
	}
	return out
}

// firstSuspectEscape 找出第一个「位于字符串里且不是合法转义」的反斜杠位置，
// 返回 -1 表示整份输入无需修补。
//
// 单独走一遍是为了让绝大多数正常请求零分配 —— 它们根本走不到重建路径。
func firstSuspectEscape(in []byte) int {
	inString := false
	for i := 0; i < len(in); i++ {
		switch c := in[i]; {
		case c == '"':
			inString = !inString
		case c == '\\' && inString:
			if i+1 >= len(in) {
				return i
			}
			switch n := in[i+1]; {
			case n == '"', n == '\\', n == '/', n == 'b', n == 'f', n == 'n', n == 'r', n == 't':
				i++
			case n == 'u':
				if i+5 < len(in) && isHex4(in[i+2:i+6]) {
					i += 5
				} else {
					return i
				}
			default:
				return i
			}
		}
	}
	return -1
}

func isHex4(b []byte) bool {
	if len(b) != 4 {
		return false
	}
	for _, c := range b {
		if _, ok := fromHex(c); !ok {
			return false
		}
	}
	return true
}
