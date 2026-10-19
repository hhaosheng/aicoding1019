package rules

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// validatePack 做 pack 级静态校验。
func validatePack(p *Pack) error {
	if p.Version == 0 {
		return fmt.Errorf("规则文件 %s (pack %s) 缺少 version 字段", p.File, p.Pack)
	}
	if p.Version > SchemaVersion {
		return fmt.Errorf("规则文件 %s (pack %s) 的 schema version=%d 高于本程序支持的 %d",
			p.File, p.Pack, p.Version, SchemaVersion)
	}
	// 协议允许在规则级覆盖，所以 pack 级为空不算错；
	// 真正「规则级与 pack 级都没有协议」的情况由 compileRule 逐条拦下。
	for i, port := range p.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("规则文件 %s (pack %s) 的 ports[%d]=%d 不是合法端口",
				p.File, p.Pack, i, port)
		}
	}
	return nil
}

// compileMatchers 编译一组匹配条件，失败时把 rule_id 一并报出 ——
// 规则写错必须 fail fast，绝不能静默跳过（否则会表现成「识别率莫名下降」，极难排查）。
func compileMatchers(ruleID, field string, ms []Matcher) ([]*regexp.Regexp, error) {
	if len(ms) == 0 {
		return nil, nil
	}
	out := make([]*regexp.Regexp, 0, len(ms))
	for i, m := range ms {
		if strings.TrimSpace(m.Regex) == "" {
			return nil, fmt.Errorf("规则 %s 的 %s[%d] 缺少 regex", ruleID, field, i)
		}
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return nil, fmt.Errorf("规则 %s 的 %s[%d] 正则非法 (pattern=%q): %w", ruleID, field, i, m.Regex, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// validate 校验权重取值范围与上限关系。
func (s Score) validate(owner string) error {
	fields := []struct {
		name string
		val  *float64
	}{
		{"protocol", s.Protocol},
		{"product", s.Product},
		{"version", s.Version},
		{"os_hint", s.OSHint},
		{"port_agree", s.PortAgree},
		{"ceiling", s.Ceiling},
		{"ceiling_no_version", s.CeilingNoVersion},
	}
	for _, f := range fields {
		if f.val == nil {
			continue
		}
		v := *f.val
		if math.IsNaN(v) || v < 0 || v > 1 {
			return fmt.Errorf("%s 的 score.%s=%v 超出 [0,1]", owner, f.name, v)
		}
	}
	if s.Ceiling != nil && s.CeilingNoVersion != nil && *s.CeilingNoVersion > *s.Ceiling {
		return fmt.Errorf("%s 的 score.ceiling_no_version=%v 大于 score.ceiling=%v：未抽到版本时上限不应更高",
			owner, *s.CeilingNoVersion, *s.Ceiling)
	}
	return nil
}
