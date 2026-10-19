// Package api 提供 HTTP 接口层。
//
// 响应体形状是刻意决定的：`POST /fingerprint` 返回的就是一个**裸 JSON 数组**，
// 与任务样例逐字段一致，不额外包一层 {results: [...]}。
// 元数据（耗时、命中数、规则指纹）全部走响应头 ——
// 让调用方按样例写的解析代码一行都不用改，同时信息一点没少。
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aicoding1019/bannerd/internal/banner"
	"github.com/aicoding1019/bannerd/internal/engine"
	"github.com/aicoding1019/bannerd/internal/rules"
)

// Request 是 POST /fingerprint 的请求体（裸数组形式也被接受，见 DecodeItems）。
type Request struct {
	Items []engine.Item `json:"items"`
}

// Info 是构建期注入的版本信息。
type Info struct {
	Version string
	GitSHA  string
}

// Server 持有识别引擎与 HTTP 组装。
type Server struct {
	eng          *engine.Engine
	info         Info
	log          *slog.Logger
	maxBody      int64
	defaultDebug bool
	started      time.Time

	// 自检探针的短 TTL 缓存。/health 与 /fingerprint 共用它，
	// 使得「服务是否还能正确识别」这件事只有一个判断来源。
	probeMu  sync.Mutex
	probeAt  time.Time
	probeRes []ProbeResult

	handler http.Handler
}

// New 组装路由与中间件。
func New(eng *engine.Engine, info Info, log *slog.Logger, maxBody int64, defaultDebug bool) *Server {
	s := &Server{
		eng:          eng,
		info:         info,
		log:          log,
		maxBody:      maxBody,
		defaultDebug: defaultDebug,
		started:      time.Now(),
	}

	mux := http.NewServeMux()
	// Go 1.22 的 ServeMux 原生支持「方法 + 路径」模式，
	// 于是「用错方法」这件事由标准库统一给出 405，而不是靠手写 if 判断。
	mux.HandleFunc("POST /fingerprint", s.handleFingerprint)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("/", s.handleFallback)

	s.handler = s.withMiddleware(mux)
	return s
}

// Handler 返回可直接挂到 http.Server 上的处理器。
func (s *Server) Handler() http.Handler { return s.handler }

// ---------------------------------------------------------------- 中间件

// statusRecorder 记录状态码与响应字节数，供访问日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := newRequestID()
		rec := &statusRecorder{ResponseWriter: w}
		rec.Header().Set("X-Request-Id", reqID)

		defer func() {
			if p := recover(); p != nil {
				// 引擎已经对每一条数据做了 recover；能走到这里说明是
				// handler 自身的缺陷。绝不能因为一个请求把整个进程带走，
				// 于是降级成 500 并把栈打进日志。
				s.log.Error("handler panic",
					"request_id", reqID, "path", r.URL.Path, "panic", fmt.Sprint(p),
					"stack", string(debug.Stack()))
				if rec.status == 0 {
					writeError(rec, http.StatusInternalServerError, "internal_error", "服务内部错误")
				}
			}
			s.log.Info("http",
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr,
			)
		}()

		if r.Body != nil {
			// 硬上限在**读取**阶段生效：超限直接失败，而不是先把几十 MB
			// 读进内存再判断。128M 内存限额的容器经不起后者。
			r.Body = http.MaxBytesReader(rec, r.Body, s.maxBody)
		}
		next.ServeHTTP(rec, r)
	})
}

// ---------------------------------------------------------------- 路由

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "bannerd",
		"version": s.info.Version,
		"git_sha": s.info.GitSHA,
		"endpoints": []map[string]string{
			{"method": "POST", "path": "/fingerprint", "desc": "批量 banner 指纹识别；请求体为 [{ip,port,banner}] 或 {items:[...]}，响应为 [{ip,port,protocol,product,version,os_hint,confidence}]"},
			{"method": "GET", "path": "/health", "desc": "健康检查；实时跑一组探针 banner 过识别引擎，规则被改坏则返回 503"},
		},
	})
}

func (s *Server) handleFallback(w http.ResponseWriter, r *http.Request) {
	// 把「路径对但方法错」和「路径根本不存在」区分开：
	// 前者是调用方的笔误，给出 405 与 Allow 头比 404 有用得多。
	switch r.URL.Path {
	case "/fingerprint":
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "/fingerprint 只接受 POST")
	case "/health":
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "/health 只接受 GET")
	default:
		writeError(w, http.StatusNotFound, "not_found", "未知路径 "+r.URL.Path)
	}
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large",
				fmt.Sprintf("请求体超过上限 %d 字节，请分批发送", tooLarge.Limit))
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "读取请求体失败："+err.Error())
		return
	}

	items, err := DecodeItems(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "请求体不是合法的记录数组："+err.Error())
		return
	}

	debug := s.defaultDebug || isTruthy(r.URL.Query().Get("debug"))
	results := s.eng.FingerprintAllOpt(items, debug)

	identified, unknown := 0, 0
	for _, res := range results {
		if res.IsUnknown() {
			unknown++
		} else {
			identified++
		}
	}

	h := w.Header()
	h.Set("X-Bannerd-Rules-Sha256", s.eng.RuleSet().SHA256())
	h.Set("X-Bannerd-Items", strconv.Itoa(len(results)))
	h.Set("X-Bannerd-Identified", strconv.Itoa(identified))
	h.Set("X-Bannerd-Unknown", strconv.Itoa(unknown))
	h.Set("X-Bannerd-Duration-Ms", strconv.FormatInt(time.Since(start).Milliseconds(), 10))

	// 自检不过时**仍然返回 200 与结果**，只加一个头把实情说出来。
	//
	// 这里刻意不做成 503：挂载外部规则目录（本项目的明确卖点）本来就会让
	// 内置探针覆盖不到某些协议。若因此让 /fingerprint 硬失败，
	// 「换个规则文件就能改识别能力」这件事就变成了「一换就报错」。
	// 判断服务健康与否是 /health 的职责，不是 /fingerprint 的。
	if failed := failedProbes(s.probeState()); failed > 0 {
		h.Set("X-Bannerd-Degraded", strconv.Itoa(failed))
	}
	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	probes := s.probeState()

	passed, failures := 0, make([]ProbeResult, 0, len(probes))
	for _, p := range probes {
		if p.Passed {
			passed++
			continue
		}
		failures = append(failures, p)
	}

	status, code := "ok", http.StatusOK
	if len(failures) > 0 {
		// 这个 503 是有牙齿的：docker-compose 里 client 的
		// depends_on.condition=service_healthy 就挂在它上面。
		// 规则被改坏 -> 探针不过 -> 503 -> healthcheck 退出码非 0 -> 容器 unhealthy。
		status, code = "degraded", http.StatusServiceUnavailable
	}

	rs := s.eng.RuleSet()
	writeJSON(w, code, healthResponse{
		Status:  status,
		Version: s.info.Version,
		GitSHA:  s.info.GitSHA,
		UptimeS: int64(time.Since(s.started).Seconds()),
		Rules: healthRules{
			Source:        rs.Source(),
			SchemaVersion: rules.SchemaVersion,
			Packs:         len(rs.Packs()),
			Count:         rs.Count(),
			SHA256:        rs.SHA256(),
			LoadedAt:      rs.LoadedAt().UTC().Format(time.RFC3339),
		},
		Probes: healthProbes{
			Total:    len(probes),
			Passed:   passed,
			Failures: failures,
		},
	})
}

// ---------------------------------------------------------------- 编解码

// DecodeItems 解析请求/文件里的记录数组。
//
// 同时接受两种形态：
//
//	[{"ip":...}]              裸数组 —— 任务样例与 testdata/sample_input.json 的形态
//	{"items":[{"ip":...}]}    信封 —— 便于以后加字段而不破坏兼容
//
// 解析失败时会先尝试「修补非法 JSON 转义」再重试一次：
// 真实扫描数据里 "J\x00\x00\x00\n8.0.32\x00" 这种写法不是合法 JSON，
// 严格解析器会把**整份文件**判错。一条脏数据让整批数据全丢，
// 正是任务要求里最不能接受的那种失败。
func DecodeItems(body []byte) ([]engine.Item, error) {
	items, err := parseItems(body)
	if err == nil {
		return items, nil
	}
	if repaired := banner.RepairJSONEscapes(body); !bytes.Equal(repaired, body) {
		if items2, err2 := parseItems(repaired); err2 == nil {
			return items2, nil
		}
	}
	return nil, err
}

func parseItems(body []byte) ([]engine.Item, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("请求体为空")
	}
	if trimmed[0] == '[' {
		var arr []engine.Item
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		if arr == nil {
			arr = []engine.Item{}
		}
		return arr, nil
	}
	// 刻意不开 DisallowUnknownFields：对输入宽容，
	// 上游扫描器多带几个我们不认识的字段不该导致整批失败。
	var env Request
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, err
	}
	if env.Items == nil {
		env.Items = []engine.Item{}
	}
	return env.Items, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeError 统一错误体。
//
// request_id 同时出现在响应头和响应体里：头是给基础设施（代理/日志）用的，
// 体是给调用方直接贴进工单用的。省掉「请提供 X-Request-Id 头」这一步往返。
func writeError(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, map[string]any{
		"error": map[string]any{
			"code":       kind,
			"message":    msg,
			"request_id": w.Header().Get("X-Request-Id"),
		},
	})
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---------------------------------------------------------------- 健康检查负载

type healthResponse struct {
	Status  string       `json:"status"`
	Version string       `json:"version"`
	GitSHA  string       `json:"git_sha"`
	UptimeS int64        `json:"uptime_s"`
	Rules   healthRules  `json:"rules"`
	Probes  healthProbes `json:"probes"`
}

type healthRules struct {
	Source string `json:"source"`
	// SchemaVersion 是规则文件的 schema 版本（不是规则条数），
	// 用来回答「这份规则文件能不能被当前二进制理解」。
	SchemaVersion int    `json:"schema_version"`
	Packs         int    `json:"packs"`
	Count         int    `json:"count"`
	SHA256        string `json:"sha256"`
	LoadedAt      string `json:"loaded_at"`
}

type healthProbes struct {
	Total    int           `json:"total"`
	Passed   int           `json:"passed"`
	Failures []ProbeResult `json:"failures"`
}

// newRequestID 生成短请求 ID。
//
// 不用 UUID：日志里人眼比对时 16 位十六进制已经足够区分，
// 而且可以直接从 slog 输出里复制粘贴去 grep。
func newRequestID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}
