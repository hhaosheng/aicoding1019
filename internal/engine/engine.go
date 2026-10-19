package engine

import (
	"runtime"
	"sync"

	"github.com/aicoding1019/bannerd/internal/banner"
	"github.com/aicoding1019/bannerd/internal/rules"
)

// Engine 是并发安全的识别引擎。
//
// 安全性来自「不可变」：RuleSet 在启动时构建一次，之后只读；
// 识别过程不写任何共享状态。因此 HTTP handler 可以任意并发调用，
// 不需要加锁 —— 加锁反而会在批量请求下变成瓶颈。
type Engine struct {
	rs *rules.RuleSet
}

// New 构造引擎。
func New(rs *rules.RuleSet) *Engine { return &Engine{rs: rs} }

// RuleSet 暴露底层规则集，供 /health 汇报规则指纹。
func (e *Engine) RuleSet() *rules.RuleSet { return e.rs }

// RulesCount 是当前生效的规则条数。
func (e *Engine) RulesCount() int { return e.rs.Count() }

// Fingerprint 识别单条记录（不带 debug 负载）。
func (e *Engine) Fingerprint(it Item) Result { return e.FingerprintOpt(it, false) }

// FingerprintAll 批量识别（不带 debug 负载）。
func (e *Engine) FingerprintAll(items []Item) []Result { return e.FingerprintAllOpt(items, false) }

// FingerprintAllOpt 批量识别。
//
// 大 batch 会按 CPU 数并行，但结果**严格按输入下标回填**：
// 并发只影响耗时，不影响输出顺序与内容 —— 同一份输入永远得到同一份输出，
// 这是黄金文件测试能成立的前提。
//
// 唯一的例外是 panic：某条记录把引擎搞崩时，只有它自己降级为 unknown，
// 其余记录与顺序都不受影响（见 FingerprintOpt 的 recover）。
func (e *Engine) FingerprintAllOpt(items []Item, debug bool) []Result {
	out := make([]Result, len(items))
	if len(items) == 0 {
		return out
	}

	// 小批量串行更快：起 goroutine 的开销比识别本身还大。
	const parallelThreshold = 64
	workers := runtime.NumCPU()
	if len(items) < parallelThreshold || workers <= 1 {
		for i, it := range items {
			out[i] = e.FingerprintOpt(it, debug)
		}
		return out
	}

	if workers > len(items) {
		workers = len(items)
	}
	var (
		wg   sync.WaitGroup
		next atomicCounter
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := next.inc()
				if i >= len(items) {
					return
				}
				out[i] = e.FingerprintOpt(items[i], debug)
			}
		}()
	}
	wg.Wait()
	return out
}

// atomicCounter 用 mutex 而不是 atomic，是为了避免为一次批量识别
// 引入 sync/atomic 的额外类型体操 —— 这里的临界区只有一次自增，
// 竞争程度远低于每轮做的正则匹配。
type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) inc() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.n
	c.n++
	return i
}

// FingerprintOpt 识别单条记录，debug 为真时附带命中的规则与候选列表。
//
// 本函数**永远不会把 panic 抛给调用方**。这不是防御性编程的洁癖，
// 而是任务里的硬要求：「不允许因为认不出来就报错崩掉」。
// 规则正则、命名捕获组下标、base64 解码都存在理论上出错的路径，
// 而这些路径全部由外部数据触发。一条脏数据最多毁掉它自己这条记录，
// 不允许毁掉整批请求，更不允许毁掉进程。
func (e *Engine) FingerprintOpt(it Item, debug bool) (res Result) {
	res = Unknown(it.IP, it.Port)

	defer func() {
		if r := recover(); r != nil {
			res = Unknown(it.IP, it.Port)
			if debug {
				res.Debug = &Debug{Recovered: true, Note: "识别过程panic，已降级为unknown"}
			}
		}
	}()

	raw, err := banner.Input(it.Banner, it.BannerB64)
	if err != nil {
		// 只有 banner_b64 非法 base64 才会走到这里。判定失败的输入不该是
		// 服务器错误：它在语义上等价于「这条没采到可用 banner」。
		if debug {
			res.Debug = &Debug{Note: "banner_b64 解码失败：" + err.Error()}
		}
		return res
	}

	d := banner.DecodeBytes(raw)
	if debug {
		res.Debug = &Debug{
			BannerLen:  d.Len,
			HadEscapes: d.HadEscapes,
			HadNUL:     d.HadNUL,
			Binary:     d.Binary,
			Truncated:  d.Truncated,
		}
	}

	var cands []hit
	best, ok := e.best(d, it.Port, debug, &cands)
	if !ok {
		return res // 保持 unknown
	}

	res.Protocol = best.rule.ProtocolName()
	res.Product = best.cap.Product
	res.Version = best.cap.Version
	res.OSHint = best.cap.OSHint
	res.Confidence = best.score

	if debug && res.Debug != nil {
		res.Debug.RuleID = best.rule.ID
		res.Debug.Pack = best.rule.Pack.Pack
		res.Debug.Form = string(best.form)
		res.Debug.Named = best.cap.Named
		// 候选按分数倒序，与人读报告的直觉一致。
		sortHits(cands)
		res.Debug.Candidates = make([]Candidate, 0, len(cands))
		for _, h := range cands {
			res.Debug.Candidates = append(res.Debug.Candidates, Candidate{
				RuleID:      h.rule.ID,
				Pack:        h.rule.Pack.Pack,
				Protocol:    h.rule.ProtocolName(),
				Product:     h.cap.Product,
				Version:     h.cap.Version,
				OSHint:      h.cap.OSHint,
				Confidence:  h.score,
				Specificity: h.rule.Specificity,
				Form:        string(h.form),
			})
		}
	}
	return res
}

// hit 是一次「规则 × 匹配形态」的命中。
type hit struct {
	rule  *rules.Compiled
	cap   rules.Capture
	score float64
	form  banner.FormName
}

// beats 是全序比较：先比置信度，再比规则的特异性，最后用加载序兜底。
//
// 三级比较的存在是为了**确定性**：同一份输入在同一份规则下必须恒等输出。
// 只比置信度时，两条同分规则谁先被遍历到就决定了结果，
// 而遍历顺序会随规则文件名的字典序、甚至 map 迭代顺序而变 ——
// 黄金文件测试会随机地挂。
func (h hit) beats(o hit) bool {
	if h.score != o.score {
		return h.score > o.score
	}
	if h.rule.Specificity != o.rule.Specificity {
		return h.rule.Specificity > o.rule.Specificity
	}
	return h.rule.Order() < o.rule.Order()
}

func sortHits(hs []hit) {
	// 规则总数是几十条量级，插入排序足够，且省掉一次 sort.Slice 的反射开销。
	for i := 1; i < len(hs); i++ {
		for j := i; j > 0 && hs[j].beats(hs[j-1]); j-- {
			hs[j], hs[j-1] = hs[j-1], hs[j]
		}
	}
}

// best 在所有规则与匹配形态中选出最优命中。
//
// 双模匹配：先拿「转义还原后的字节精确形态」跑一遍；只有一条都没命中时，
// 才退回到「未还原转义的原文」再跑一遍。
//
// 为什么按这个顺序、而不是无条件跑两遍：两种形态对同一份数据可能给出不同解释，
// 此时必须先信还原后的那个 —— 它才是线路上的真实字节。退化匹配只是为了兜住
// 「上游把二进制 banner 原样塞进 JSON」这类没能还原干净的边角情况。
func (e *Engine) best(d banner.Decoded, port int, collect bool, out *[]hit) (hit, bool) {
	var (
		best  hit
		found bool
	)
	for _, f := range d.MatchForms() {
		for _, r := range e.rs.Rules() {
			cap, ok := r.Match(f.Data)
			if !ok {
				continue
			}
			h := hit{rule: r, cap: cap, score: scoreRule(r, cap, port), form: f.Name}
			if !found || h.beats(best) {
				best, found = h, true
			}
			if collect && out != nil {
				*out = append(*out, h)
			}
		}
		if found {
			break
		}
	}
	return best, found
}
