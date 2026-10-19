package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aicoding1019/bannerd/internal/api"
	"github.com/aicoding1019/bannerd/internal/engine"
	"github.com/aicoding1019/bannerd/internal/rules"
)

const maxBody = 8 << 20

func newServer(t *testing.T) (*api.Server, *engine.Engine) {
	t.Helper()
	rs, err := rules.Load(rules.Options{})
	if err != nil {
		t.Fatalf("加载规则失败：%v", err)
	}
	eng := engine.New(rs)
	// 丢弃日志：测试关注的是响应，不是日志行。
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.New(eng, api.Info{Version: "test", GitSHA: "deadbee"}, log, maxBody, false), eng
}

func do(t *testing.T, s *api.Server, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("读取 %s 失败：%v", name, err)
	}
	return b
}

// TestFingerprintReturnsBareArray 是接口形状的核心断言：
// 响应体就是一个裸数组，与任务样例逐字段一致，不多包一层信封。
func TestFingerprintReturnsBareArray(t *testing.T) {
	s, _ := newServer(t)
	w := do(t, s, http.MethodPost, "/fingerprint", readFile(t, "sample_input.json"))

	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type 应为 application/json，实际 %q", ct)
	}

	raw := bytes.TrimSpace(w.Body.Bytes())
	if len(raw) == 0 || raw[0] != '[' {
		t.Fatalf("响应体必须是裸 JSON 数组，实际开头为 %q", firstBytes(raw, 40))
	}

	var got []engine.Result
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("响应体不是合法结果数组：%v", err)
	}

	var want []engine.Result
	if err := json.Unmarshal(readFile(t, "expected_20.json"), &want); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("结果条数 %d != 期望 %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条不符：\n 期望 %+v\n 实际 %+v", i+1, want[i], got[i])
		}
	}
}

// TestLooseEscapesFileGivesIdenticalResults 是端到端的「双通道等价」验证：
// 同一份数据的两种 JSON 写法（合法 \u0000 与字面量 \x00）必须给出**完全相同**的结果。
// 上游扫描器用哪种写法，不该影响识别结论。
func TestLooseEscapesFileGivesIdenticalResults(t *testing.T) {
	s, _ := newServer(t)

	strict := do(t, s, http.MethodPost, "/fingerprint", readFile(t, "sample_input.json"))
	loose := do(t, s, http.MethodPost, "/fingerprint", readFile(t, "sample_input_loose.json"))

	if loose.Code != http.StatusOK {
		t.Fatalf("含字面量 \\x00 的输入必须是 200（修补后解析），实际 %d：%s", loose.Code, loose.Body.String())
	}
	if loose.Body.String() != strict.Body.String() {
		t.Fatalf("两种转义写法结果不一致\n 合法转义: %s\n 字面量  : %s",
			firstBytes(strict.Body.Bytes(), 200), firstBytes(loose.Body.Bytes(), 200))
	}
}

func TestFingerprintAcceptsEnvelope(t *testing.T) {
	s, _ := newServer(t)
	body := []byte(`{"items":[{"ip":"9.9.9.9","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}]}`)
	w := do(t, s, http.MethodPost, "/fingerprint", body)

	if w.Code != http.StatusOK {
		t.Fatalf("信封形态应被接受，实际 %d：%s", w.Code, w.Body.String())
	}
	var got []engine.Result
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Protocol != "SSH" || got[0].Version != "9.3" {
		t.Fatalf("信封形态结果异常：%+v", got)
	}
}

// TestUnknownIsReturnedNotRaised：认不出来的记录照样在结果数组里，且是 unknown。
func TestUnknownIsReturnedNotRaised(t *testing.T) {
	s, _ := newServer(t)
	body := []byte(`[
	  {"ip":"1.1.1.1","port":12345,"banner":"QUIT\r\n"},
	  {"ip":"1.1.1.2","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}
	]`)
	w := do(t, s, http.MethodPost, "/fingerprint", body)

	if w.Code != http.StatusOK {
		t.Fatalf("认不出来绝不能变成错误状态码，实际 %d：%s", w.Code, w.Body.String())
	}
	var got []engine.Result
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("结果必须 1:1 对应输入，实际 %d 条", len(got))
	}
	if got[0].Protocol != "unknown" {
		t.Fatalf("第一条应为 unknown，实际 %q", got[0].Protocol)
	}
	if got[1].Protocol != "SSH" {
		t.Fatalf("一条脏数据不该影响其余记录，第二条实际 %q", got[1].Protocol)
	}
}

func TestEmptyArrayIsOK(t *testing.T) {
	s, _ := newServer(t)
	w := do(t, s, http.MethodPost, "/fingerprint", []byte(`[]`))
	if w.Code != http.StatusOK {
		t.Fatalf("空数组应返回 200，实际 %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("空数组应回 []，实际 %q", got)
	}
}

func TestMalformedJSONReturns400(t *testing.T) {
	s, _ := newServer(t)
	for _, body := range []string{`{oops`, `[{"ip":}]`, ``, `"just a string"`, `[1,2,3]`} {
		w := do(t, s, http.MethodPost, "/fingerprint", []byte(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("输入 %q 应返回 400，实际 %d：%s", body, w.Code, w.Body.String())
			continue
		}
		var e struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
			t.Errorf("错误体不是 JSON：%v", err)
			continue
		}
		if e.Error.Code == "" || e.Error.Message == "" || e.Error.RequestID == "" {
			t.Errorf("错误体三字段都应非空，实际 %+v", e.Error)
		}
		if e.Error.RequestID != w.Header().Get("X-Request-Id") {
			t.Errorf("体内 request_id 应与 X-Request-Id 头一致")
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s, _ := newServer(t)

	w := do(t, s, http.MethodGet, "/fingerprint", nil)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /fingerprint 应为 405，实际 %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("405 应带 Allow: POST，实际 %q", allow)
	}

	w = do(t, s, http.MethodPost, "/health", []byte(`{}`))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /health 应为 405，实际 %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET" {
		t.Fatalf("405 应带 Allow: GET，实际 %q", allow)
	}
}

func TestNotFound(t *testing.T) {
	s, _ := newServer(t)
	w := do(t, s, http.MethodGet, "/no/such/path", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("未知路径应为 404，实际 %d", w.Code)
	}
}

// TestBodyTooLarge：超限在**读取阶段**就失败，而不是先读进内存再判断。
func TestBodyTooLarge(t *testing.T) {
	rs, err := rules.Load(rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	small := api.New(engine.New(rs), api.Info{Version: "t"}, slog.New(slog.NewTextHandler(io.Discard, nil)), 64, false)

	w := do(t, small, http.MethodPost, "/fingerprint", readFile(t, "sample_input.json"))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限应为 413，实际 %d：%s", w.Code, w.Body.String())
	}
}

// TestHealthIsARealSelfTest：/health 必须真的跑识别，而不是回一句 ok。
func TestHealthIsARealSelfTest(t *testing.T) {
	s, _ := newServer(t)
	w := do(t, s, http.MethodGet, "/health", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("内置规则下健康检查应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var h struct {
		Status string `json:"status"`
		Rules  struct {
			Source        string `json:"source"`
			SchemaVersion int    `json:"schema_version"`
			Packs         int    `json:"packs"`
			Count         int    `json:"count"`
			SHA256        string `json:"sha256"`
			LoadedAt      string `json:"loaded_at"`
		} `json:"rules"`
		Probes struct {
			Total    int `json:"total"`
			Passed   int `json:"passed"`
			Failures []struct {
				Name string `json:"name"`
				Got  string `json:"got"`
				Want string `json:"want"`
			} `json:"failures"`
		} `json:"probes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}

	if h.Status != "ok" {
		t.Fatalf("status 应为 ok，实际 %q", h.Status)
	}
	if h.Probes.Total == 0 || h.Probes.Passed != h.Probes.Total {
		t.Fatalf("探针应全部通过，实际 %d/%d，失败项 %+v", h.Probes.Passed, h.Probes.Total, h.Probes.Failures)
	}
	if h.Rules.Count < 20 || len(h.Rules.SHA256) != 64 || h.Rules.LoadedAt == "" {
		t.Fatalf("规则指纹信息不完整：%+v", h.Rules)
	}
	if h.Rules.Packs == 0 {
		t.Fatalf("应汇报 pack 数量，实际 %+v", h.Rules)
	}
	if h.Rules.Source != "embedded" {
		t.Fatalf("默认应使用内置规则，实际 source=%q", h.Rules.Source)
	}
}

// TestHealthDegradesWhenRulesBreak 是「健康检查有牙齿」的证明：
// 把 SSH 规则换成一个不认 OpenSSH 的版本，探针就该失败、/health 就该 503。
func TestHealthDegradesWhenRulesBreak(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "ssh.yaml"), []byte(`
version: 1
pack: ssh
protocol: SSH
rules:
  - id: ssh.only_my_impl
    match:
      - regex: '^SSH-2\.0-MySSH_(?P<version>[0-9.]+)'
    product: MySSH
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	rs, err := rules.Load(rules.Options{Dir: dir})
	if err != nil {
		t.Fatalf("加载外部规则失败：%v", err)
	}
	s := api.New(engine.New(rs), api.Info{Version: "t"}, slog.New(slog.NewTextHandler(io.Discard, nil)), maxBody, false)

	w := do(t, s, http.MethodGet, "/health", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("规则被换坏后 /health 应为 503，实际 %d：%s", w.Code, w.Body.String())
	}

	var h struct {
		Status string `json:"status"`
		Probes struct {
			Passed   int `json:"passed"`
			Total    int `json:"total"`
			Failures []struct {
				Name string `json:"name"`
				Got  string `json:"got"`
				Want string `json:"want"`
			} `json:"failures"`
		} `json:"probes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != "degraded" {
		t.Fatalf("status 应为 degraded，实际 %q", h.Status)
	}
	if len(h.Probes.Failures) == 0 {
		t.Fatal("degraded 时必须给出失败项明细")
	}
	for _, f := range h.Probes.Failures {
		if f.Name == "" || f.Want == "" || f.Got == "" {
			t.Errorf("失败项应带 name/want/got 便于定位，实际 %+v", f)
		}
	}
	t.Logf("degraded 明细：%+v", h.Probes.Failures)

	// 关键：识别接口仍然可用，并如实通过响应头告知降级 ——
	// 挂外部规则目录是明确卖点，不该因此让识别彻底不可用。
	fw := do(t, s, http.MethodPost, "/fingerprint",
		[]byte(`[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-MySSH_1.2"}]`))
	if fw.Code != http.StatusOK {
		t.Fatalf("/fingerprint 不该因为探针失败而变 503，实际 %d", fw.Code)
	}
	if fw.Header().Get("X-Bannerd-Degraded") == "" {
		t.Fatal("探针失败时应通过 X-Bannerd-Degraded 头如实告知")
	}
}

// TestMetadataHeaders：元数据走响应头，响应体保持裸数组。
func TestMetadataHeaders(t *testing.T) {
	s, eng := newServer(t)
	w := do(t, s, http.MethodPost, "/fingerprint", readFile(t, "sample_input.json"))

	for _, name := range []string{
		"X-Request-Id", "X-Bannerd-Rules-Sha256", "X-Bannerd-Items",
		"X-Bannerd-Identified", "X-Bannerd-Unknown", "X-Bannerd-Duration-Ms",
	} {
		if w.Header().Get(name) == "" {
			t.Errorf("缺少响应头 %s", name)
		}
	}
	if got := w.Header().Get("X-Bannerd-Rules-Sha256"); got != eng.RuleSet().SHA256() {
		t.Errorf("规则指纹头与引擎不一致：%q vs %q", got, eng.RuleSet().SHA256())
	}
	if w.Header().Get("X-Bannerd-Items") != "20" {
		t.Errorf("X-Bannerd-Items 应为 20，实际 %q", w.Header().Get("X-Bannerd-Items"))
	}
	if w.Header().Get("X-Bannerd-Unknown") != "1" {
		t.Errorf("样例里恰好 1 条 unknown，实际 %q", w.Header().Get("X-Bannerd-Unknown"))
	}
}

// TestDebugQueryParam：?debug=1 打开诊断负载，默认关闭。
func TestDebugQueryParam(t *testing.T) {
	s, _ := newServer(t)
	body := []byte(`[{"ip":"1.1.1.1","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}]`)

	plain := do(t, s, http.MethodPost, "/fingerprint", body)
	if strings.Contains(plain.Body.String(), "\"debug\"") {
		t.Fatalf("默认响应不该含 debug 字段：%s", plain.Body.String())
	}

	dbg := do(t, s, http.MethodPost, "/fingerprint?debug=1", body)
	if !strings.Contains(dbg.Body.String(), "\"debug\"") {
		t.Fatalf("?debug=1 应带诊断负载：%s", dbg.Body.String())
	}
}

// TestIndexListsEndpoints：根路径给出一份可发现性元数据。
func TestIndexListsEndpoints(t *testing.T) {
	s, _ := newServer(t)
	w := do(t, s, http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / 应返回 200，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/fingerprint") || !strings.Contains(w.Body.String(), "/health") {
		t.Fatalf("根路径应列出两个端点：%s", w.Body.String())
	}
}

// TestNULAndBinarySurviveTheRoundTrip：banner_b64 是二进制 banner 的无损通道。
func TestNULAndBinarySurviveTheRoundTrip(t *testing.T) {
	s, _ := newServer(t)
	// "J\x00\x00\x00\n8.0.32\x00"
	body := []byte(`[{"ip":"1.1.1.1","port":3306,"banner_b64":"SgAAAAo4LjAuMzIA"}]`)
	w := do(t, s, http.MethodPost, "/fingerprint", body)
	if w.Code != http.StatusOK {
		t.Fatalf("banner_b64 通道应被接受，实际 %d：%s", w.Code, w.Body.String())
	}
	var got []engine.Result
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got[0].Protocol != "MySQL" || got[0].Version != "8.0.32" {
		t.Fatalf("banner_b64 通道识别失败：%+v", got[0])
	}
}

func firstBytes(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
