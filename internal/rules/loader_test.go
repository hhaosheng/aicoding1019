package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePack(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("写临时规则文件失败：%v", err)
	}
}

func TestLoadEmbedded(t *testing.T) {
	rs, err := Load(Options{})
	if err != nil {
		t.Fatalf("加载内置规则失败：%v", err)
	}
	if rs.Source() != "embedded" {
		t.Fatalf("source 应为 embedded，实际 %q", rs.Source())
	}
	if rs.Count() < 20 {
		t.Fatalf("内置规则条数偏少，只有 %d 条", rs.Count())
	}
	if len(rs.SHA256()) != 64 {
		t.Fatalf("sha256 长度异常：%q", rs.SHA256())
	}

	// 任务必答的五个协议必须在内置规则里各有着落。
	protos := map[string]int{}
	for _, r := range rs.Rules() {
		protos[r.ProtocolName()]++
	}
	for _, want := range []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"} {
		if protos[want] == 0 {
			t.Errorf("内置规则里没有任何 %s 规则", want)
		}
	}
	t.Logf("内置规则：%d 个 pack / %d 条规则 / 命中协议 %v", len(rs.Packs()), rs.Count(), protos)
}

// TestExternalPackReplacesWholeFile 是 ADR-009 的可执行说明：
// 挂载一份 http.yaml 应当**完整接管** HTTP 识别，而不是和内置规则做并集。
// 否则「我覆盖了 http.yaml 但内置的 nginx 规则还在」这种行为
// 只能靠读引擎源码才能推断出来。
func TestExternalPackReplacesWholeFile(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "http.yaml", `
version: 1
pack: http
protocol: HTTP
ports: [80, 8080]
rules:
  - id: custom.http.httpd
    specificity: 100
    match:
      - regex: '(?i)^HTTP/1\.[01] .*Server: (?P<product>httpd)/(?P<version>[0-9.]+)'
    product: httpd
`)

	base, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	over, err := Load(Options{Dir: dir})
	if err != nil {
		t.Fatalf("加载外部规则失败：%v", err)
	}

	if over.Source() != dir {
		t.Fatalf("source 应为外部目录 %q，实际 %q", dir, over.Source())
	}
	if over.Count() >= base.Count() {
		t.Fatalf("整文件替换后规则数应减少：内置 %d -> 覆盖后 %d", base.Count(), over.Count())
	}
	if over.SHA256() == base.SHA256() {
		t.Fatal("替换了规则内容，sha256 却不变")
	}

	var hasCustom, hasBuiltinNginx bool
	for _, r := range over.Rules() {
		switch r.ID {
		case "custom.http.httpd":
			hasCustom = true
		case "http.nginx":
			hasBuiltinNginx = true
		}
	}
	if !hasCustom {
		t.Error("外部 pack 的规则未生效")
	}
	if hasBuiltinNginx {
		t.Error("同名 pack 应为整文件替换，但内置的 http.nginx 仍然存在")
	}

	// 未被覆盖的 pack 必须原封不动地保留 —— 覆盖一份不该影响其余。
	var stillHasSSH bool
	for _, r := range over.Rules() {
		if strings.HasPrefix(r.ID, "ssh.") {
			stillHasSSH = true
			break
		}
	}
	if !stillHasSSH {
		t.Error("只覆盖了 http pack，SSH 规则却消失了")
	}
}

// TestInvalidRegexFailsFastWithRuleID：非法正则必须在**启动期**炸出来并点名规则，
// 而不是被静默跳过、表现为「这条规则莫名其妙不生效」。
func TestInvalidRegexFailsFastWithRuleID(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "http.yaml", `
version: 1
pack: http
protocol: HTTP
rules:
  - id: broken.regex.rule
    match:
      - regex: '^HTTP/([0-9'
`)

	_, err := Load(Options{Dir: dir})
	if err == nil {
		t.Fatal("非法正则应当在加载期报错")
	}
	if !strings.Contains(err.Error(), "broken.regex.rule") {
		t.Fatalf("错误信息必须点名出错的规则 id，实际：%v", err)
	}
}

func TestUnknownYAMLFieldIsRejected(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "typo.yaml", `
version: 1
pack: typo
protocol: TYPO
rules:
  - id: typo.rule
    specificty: 100
    match:
      - regex: 'x'
`)
	_, err := Load(Options{Dir: dir})
	if err == nil {
		t.Fatal("字段名拼错应当在加载期报错（KnownFields）")
	}
	if !strings.Contains(err.Error(), "specificty") {
		t.Fatalf("错误信息应指出拼错的字段名，实际：%v", err)
	}
}

func TestDuplicateRuleIDRejected(t *testing.T) {
	dir := t.TempDir()
	// 与内置 ssh.openssh 撞 id
	writePack(t, dir, "dup.yaml", `
version: 1
pack: dup
protocol: DUP
rules:
  - id: ssh.openssh
    match:
      - regex: 'x'
`)
	_, err := Load(Options{Dir: dir})
	if err == nil {
		t.Fatal("规则 id 全局唯一，重复应报错")
	}
	if !strings.Contains(err.Error(), "ssh.openssh") {
		t.Fatalf("错误信息应点名重复的 id，实际：%v", err)
	}
}

func TestMissingRulesDirIsError(t *testing.T) {
	if _, err := Load(Options{Dir: filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Fatal("不存在的规则目录应报错，而不是静默退回内置规则")
	}
}

func TestEmptyRulesDirIsError(t *testing.T) {
	if _, err := Load(Options{Dir: t.TempDir()}); err == nil {
		t.Fatal("空规则目录应报错（几乎总是挂载路径写错了）")
	}
}

func TestNoMatchConditionIsError(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "nomatch.yaml", `
version: 1
pack: nomatch
protocol: NOMATCH
rules:
  - id: nomatch.rule
    description: "永远不会命中"
`)
	_, err := Load(Options{Dir: dir})
	if err == nil {
		t.Fatal("没有任何 match 条件的规则应被判为错误")
	}
}

// TestScoreInheritanceChain 验证「规则 -> pack -> 基线」三级继承。
func TestScoreInheritanceChain(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "chain.yaml", `
version: 1
pack: chain
protocol: CHAIN
score: {ceiling: 0.80}
rules:
  - id: chain.inherits_pack
    match:
      - regex: 'alpha'
  - id: chain.own_ceiling
    match:
      - regex: 'beta'
    score: {ceiling: 0.50, ceiling_no_version: 0.50, product: 0.20}
`)
	rs, err := Load(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*Compiled{}
	for _, r := range rs.Rules() {
		byID[r.ID] = r
	}

	// 规则不写 score：protocol 继承基线 0.60，ceiling 继承 pack 的 0.80。
	inh := byID["chain.inherits_pack"]
	if inh == nil {
		t.Fatal("chain.inherits_pack 未加载")
	}
	if got := *inh.Effective.Protocol; got != *DefaultScore.Protocol {
		t.Errorf("protocol 权重应继承基线 %.2f，实际 %.2f", *DefaultScore.Protocol, got)
	}
	if inh.Effective.Ceiling == nil || *inh.Effective.Ceiling != 0.80 {
		t.Errorf("ceiling 应继承 pack 的 0.80，实际 %v", inh.Effective.Ceiling)
	}

	// 规则写了 ceiling 与 product：覆盖 pack，未写的仍旧继承。
	own := byID["chain.own_ceiling"]
	if own.Effective.Ceiling == nil || *own.Effective.Ceiling != 0.50 {
		t.Errorf("规则级 ceiling 应覆盖 pack，实际 %v", own.Effective.Ceiling)
	}
	if own.Effective.Product == nil || *own.Effective.Product != 0.20 {
		t.Errorf("规则级 product 权重应为 0.20，实际 %v", own.Effective.Product)
	}
	if *own.Effective.Version != *DefaultScore.Version {
		t.Errorf("规则未声明的 version 权重应继承基线，实际 %.2f", *own.Effective.Version)
	}
}

// TestCeilingNoVersionNotAboveCeiling 是配置自洽性：无版本时的封顶不该高于有版本时。
func TestCeilingNoVersionNotAboveCeiling(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "bad.yaml", `
version: 1
pack: bad
protocol: BAD
rules:
  - id: bad.ceiling
    match:
      - regex: 'x'
    score: {ceiling: 0.50, ceiling_no_version: 0.90}
`)
	if _, err := Load(Options{Dir: dir}); err == nil {
		t.Fatal("ceiling_no_version > ceiling 应被判为配置错误")
	}
}

func TestEffectivePortsFallsBackToPack(t *testing.T) {
	rs, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	var openssh *Compiled
	for _, r := range rs.Rules() {
		if r.ID == "ssh.openssh" {
			openssh = r
			break
		}
	}
	if openssh == nil {
		t.Fatal("未找到 ssh.openssh")
	}
	ports := openssh.EffectivePorts()
	if len(ports) == 0 || ports[0] != 22 {
		t.Fatalf("ssh.openssh 应继承 pack 的端口先验 [22,...]，实际 %v", ports)
	}
}
