package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	bannerd "github.com/aicoding1019/bannerd"
)

// BasePackName 是承载全局权重基线的伪包名，它对应用 rules/_pack.yaml。
// 该文件不产生规则，只提供「规则 → pack → 基线」继承链的最后一环。
const BasePackName = "_base"

// Options 控制规则加载行为。
type Options struct {
	// Dir 是可选的外部规则目录。为空表示只用 go:embed 的内置规则。
	Dir string
	// Now 便于测试注入时间；为空则用 time.Now。
	Now func() time.Time
}

type rawFile struct {
	name   string // 文件名（不含目录）
	origin string // "embedded" 或外部目录路径
	data   []byte
}

// Load 加载内置规则，并按需用外部目录覆盖。
//
// 合并语义刻意做成「同名 pack 整文件替换」而不是「逐规则合并」：
// 整文件替换的结果可预测、可解释 —— 挂载一份自定义 http.yaml 就完整接管
// HTTP 识别，不会出现「内置三条 + 外部一条」这种需要读代码才能推断的混合态。
func Load(opts Options) (*RuleSet, error) {
	var raws []rawFile

	names, err := fs.Glob(bannerd.BuiltinRules, "rules/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("枚举内置规则: %w", err)
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := fs.ReadFile(bannerd.BuiltinRules, n)
		if err != nil {
			return nil, fmt.Errorf("读取内置规则 %s: %w", n, err)
		}
		raws = append(raws, rawFile{name: filepath.Base(n), origin: "embedded", data: b})
	}

	source := "embedded"
	if dir := strings.TrimSpace(opts.Dir); dir != "" {
		ext, err := readDir(dir)
		if err != nil {
			return nil, err
		}
		raws = append(raws, ext...)
		source = dir
	}

	return compileAll(raws, source, opts.Now)
}

func readDir(dir string) ([]rawFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取外部规则目录 %s: %w", dir, err)
	}
	var out []rawFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("读取外部规则 %s: %w", full, err)
		}
		out = append(out, rawFile{name: e.Name(), origin: dir, data: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	if len(out) == 0 {
		return nil, fmt.Errorf("外部规则目录 %s 下没有任何 .yaml 文件", dir)
	}
	return out, nil
}

func compileAll(raws []rawFile, source string, now func() time.Time) (*RuleSet, error) {
	if len(raws) == 0 {
		return nil, fmt.Errorf("没有加载到任何规则文件")
	}

	// 1) 解析。KnownFields(true) 让 YAML 里的字段名拼写错误在启动期就暴露，
	//    而不是表现为「这条规则莫名其妙不生效」。
	type entry struct {
		pack *Pack
		data []byte
	}
	var parsed []entry
	for _, f := range raws {
		var p Pack
		dec := yaml.NewDecoder(bytes.NewReader(f.data))
		dec.KnownFields(true)
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("解析规则文件 %s (%s): %w", f.name, f.origin, err)
		}
		p.File = f.name
		p.Origin = f.origin
		parsed = append(parsed, entry{pack: &p, data: f.data})
	}

	// 2) 同名 pack 整文件替换：内置先入，外部覆盖同位置；新名字追加。
	idx := make(map[string]int, len(parsed))
	var packs []*Pack
	bytesByName := make(map[string][]byte, len(parsed))
	for _, e := range parsed {
		name := e.pack.Pack
		if name == "" {
			return nil, fmt.Errorf("规则文件 %s 缺少 pack 字段", e.pack.File)
		}
		if i, ok := idx[name]; ok {
			packs[i] = e.pack // 整文件替换
		} else {
			idx[name] = len(packs)
			packs = append(packs, e.pack)
		}
		bytesByName[name] = e.data
	}

	// 3) 解析出权重基线。
	base := DefaultScore
	for _, p := range packs {
		if p.Pack == BasePackName {
			base = p.Score.inherit(DefaultScore)
			break
		}
	}
	if err := base.validate("_base"); err != nil {
		return nil, err
	}

	// 4) 编译规则。规则级权重继承 pack 级，pack 级继承基线。
	var compiled []*Compiled
	seen := make(map[string]string) // 规则 id -> 所属 pack
	order := 0
	for _, p := range packs {
		if err := validatePack(p); err != nil {
			return nil, err
		}
		if p.Pack == BasePackName {
			continue // 基线包不产生规则
		}
		packScore := p.Score.inherit(base)
		if err := packScore.validate(p.Pack); err != nil {
			return nil, err
		}
		for i := range p.Rules {
			r := &p.Rules[i]
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("规则 id 重复: %q 同时出现在 pack %q 与 pack %q", r.ID, prev, p.Pack)
			}
			seen[r.ID] = p.Pack

			c, err := compileRule(p, r, packScore, order)
			if err != nil {
				return nil, err
			}
			compiled = append(compiled, c)
			order++
		}
	}

	if len(compiled) == 0 {
		return nil, fmt.Errorf("规则文件解析成功但没有任何规则")
	}

	// 5) 规则包指纹：让 /health 能回答「此刻生效的是哪一版规则」。
	names := make([]string, 0, len(packs))
	for _, p := range packs {
		names = append(names, p.Pack)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00", n)
		h.Write(bytesByName[n])
		h.Write([]byte{0})
	}

	clock := now
	if clock == nil {
		clock = time.Now
	}

	return &RuleSet{
		packs:    packs,
		rules:    compiled,
		sha:      hex.EncodeToString(h.Sum(nil)),
		source:   source,
		loadedAt: clock(),
	}, nil
}

func compileRule(p *Pack, r *Rule, packScore Score, order int) (*Compiled, error) {
	if strings.TrimSpace(r.ID) == "" {
		return nil, fmt.Errorf("规则文件 %s 中存在缺少 id 的规则（pack %s）", p.File, p.Pack)
	}
	if p.Protocol == "" && r.Protocol == "" {
		return nil, fmt.Errorf("规则 %s 未声明协议：规则级与 pack %q 的 protocol 均为空", r.ID, p.Pack)
	}

	c := &Compiled{
		Rule:      *r,
		Pack:      p,
		Effective: r.Score.inherit(packScore),
		order:     order,
	}
	if err := c.Effective.validate(r.ID); err != nil {
		return nil, err
	}

	var err error
	if c.match, err = compileMatchers(r.ID, "match", r.Match); err != nil {
		return nil, err
	}
	if c.matchAny, err = compileMatchers(r.ID, "match_any", r.MatchAny); err != nil {
		return nil, err
	}
	if len(c.match) == 0 && len(c.matchAny) == 0 {
		return nil, fmt.Errorf("规则 %s 没有任何 match/match_any 条件，永远不会命中", r.ID)
	}

	c.osRegex = make([]*regexp.Regexp, len(r.OSHint))
	for i, h := range r.OSHint {
		if strings.TrimSpace(h.Regex) == "" {
			if h.Value == "" {
				return nil, fmt.Errorf("规则 %s 的第 %d 条 os_hint 既没有 regex 也没有 value", r.ID, i+1)
			}
			continue // 静态推断，恒真
		}
		re, err := regexp.Compile(h.Regex)
		if err != nil {
			return nil, fmt.Errorf("规则 %s 的 os_hint 正则非法: %w", r.ID, err)
		}
		c.osRegex[i] = re
	}
	return c, nil
}
