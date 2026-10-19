package engine

import (
	"math"

	"github.com/aicoding1019/bannerd/internal/rules"
)

// scoreRule 计算一条命中规则的置信度。
//
// 模型（与 plan.md §4.2 一致）：
//
//	confidence = min( ceiling, protocol + product + version + os_hint + port_agree )
//
// 四个刻意的设计选择，每一个都对应一类真实的翻车方式：
//
//  1. 加分项取决于「实际抽到了什么」，而不是「规则声明了什么」。
//     规则写了 product 取值为 nginx、但正则没能捕获到产品名时，那 0.15 不给。
//     否则一条只有残缺内容的 banner 也会因为「命中的规则很具体」而拿满分。
//
//  2. 没有版本信息就压低上限（ceiling_no_version）。
//     任务样例给 Redis 的置信度是 0.7 而不是 0.85，道理就在这里：
//     「只认出了协议」与「协议和版本都拿到了」不该同分。
//
//  3. 端口先验只加分、不减分（port_agree）。
//     8118 端口上的 nginx 依然是 nginx。把「非常规端口」做成扣分项，
//     等于要求真实数据长得和教科书一样 —— 这是扫描数据里最常见的翻车点。
//     样例里 TLS 出现在 9999、nginx 出现在 8443，都是这条规则在兜底。
//
//  4. 取整到小数点后两位。
//     置信度是给人看的排序信号，不是浮点运算结果；
//     固定两位小数才能让黄金文件测试逐字节可比。
func scoreRule(c *rules.Compiled, cap rules.Capture, port int) float64 {
	s := c.Effective

	total := 0.0
	if c.ProtocolName() != "" {
		total += value(s.Protocol)
	}
	// 只有真的抽到了对应字段才给分 —— 见上面第 1 条。
	if cap.Product != "" {
		total += value(s.Product)
	}
	if cap.Version != "" {
		total += value(s.Version)
	}
	if cap.OSHint != "" {
		total += value(s.OSHint)
	}
	if portAgrees(c.EffectivePorts(), port) {
		total += value(s.PortAgree)
	}

	ceiling := value(s.Ceiling)
	if cap.Version == "" {
		if v := value(s.CeilingNoVersion); v < ceiling {
			ceiling = v
		}
	}

	return round2(clamp(total, 0, ceiling))
}

// portAgrees 判断给定端口是否落在规则的端口先验内。
//
// 未声明端口时返回 false：先验缺失只能是「不加分」，
// 绝不能变成「加满分」——后者会让一条没写端口的规则凭空高人一等。
func portAgrees(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// value 读取可空权重。nil（未声明）记 0 分，而不是默认值 ——
// 继承已在加载期完成，走到这里的 nil 只可能来自「显式留空」。
func value(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// round2 保留两位小数，消除浮点累加噪声，保证同一输入恒等输出。
func round2(v float64) float64 { return math.Round(v*100) / 100 }
