// Command bannerd 是 Banner 指纹识别系统的服务端。
//
// 一个二进制承担两种角色：
//
//	bannerd                      起 HTTP 服务（默认角色）
//	bannerd healthcheck --url ... 作为容器的健康检查探针
//	bannerd rules                打印当前生效的规则清单，用于排错与演示
//
// 为什么健康检查要复用同一个二进制：运行镜像是 scratch，里面没有 shell、
// 没有 curl、没有 wget。容器里唯一存在的可执行文件就是这个二进制本身，
// 所以健康检查只能由它自证 —— 这反过来逼着 /health 必须是一个**有意义的**
// 检查，而不是回一句 {"status":"ok"} 就完事。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/aicoding1019/bannerd/internal/api"
	"github.com/aicoding1019/bannerd/internal/config"
	"github.com/aicoding1019/bannerd/internal/engine"
	"github.com/aicoding1019/bannerd/internal/rules"
)

// 这两个变量由 Dockerfile 的
// `-ldflags "-X main.version=${VERSION} -X main.gitSHA=${GIT_SHA}"` 注入。
// 保留默认值，使 `go run ./cmd/server` 在本地也总能打印出东西。
var (
	version = "dev"
	gitSHA  = "unknown"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "healthcheck":
			return runHealthcheck(args[1:])
		case "rules":
			return runRules(args[1:])
		case "version", "-version", "--version":
			fmt.Printf("bannerd %s (git %s, built with %s)\n", version, gitSHA, runtime.Version())
			return 0
		case "help", "-h", "--help":
			usage(os.Stdout)
			return 0
		}
	}
	return runServe(args)
}

func runServe(args []string) int {
	cfg, err := config.ParseServer(args, usage)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(os.Stdout)
			return 0
		}
		fmt.Fprintf(os.Stderr, "bannerd: %v\n\n", err)
		usage(os.Stderr)
		return 2
	}

	log := newLogger(cfg.LogLevel, cfg.LogFormat)

	rs, err := rules.Load(rules.Options{Dir: cfg.RulesDir})
	if err != nil {
		// 规则加载失败是**启动期**错误，必须让进程起不来。
		// 这与「运行期认不出来不报错」不矛盾：前者是配置坏了，
		// 后者是数据没认出来 —— 前者要在部署时就暴露，后者绝不能变成 5xx。
		log.Error("规则加载失败，拒绝启动", "err", err, "rules_dir", cfg.RulesDir)
		return 1
	}
	log.Info("规则加载完成",
		"source", rs.Source(),
		"packs", len(rs.Packs()),
		"rules", rs.Count(),
		"sha256", short(rs.SHA256()),
	)

	srv := api.New(engine.New(rs), api.Info{Version: version, GitSHA: gitSHA}, log, cfg.MaxBodyBytes, cfg.Debug)

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// 这四个超时是慢速攻击的基本防线。没有它们，一个只发一半
		// 请求头的连接就能长期占住一个 goroutine。
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	// SIGTERM 触发优雅停机：在途的 /fingerprint 批次会被排空，
	// 排在它后面的 client 不会看到连接被重置。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("HTTP 服务启动", "addr", cfg.Addr, "version", version, "git_sha", gitSHA)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Error("HTTP 服务异常退出", "err", err)
		return 1
	case <-ctx.Done():
		log.Info("收到停机信号，开始排空在途请求", "grace", cfg.ShutdownTimeout)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("优雅停机超时，强制关闭", "err", err)
		_ = httpSrv.Close()
		return 1
	}
	log.Info("已优雅停机")
	return 0
}

// runRules 打印当前生效的规则清单。
//
// 存在的意义是回答「此刻到底加载了哪些规则、来自哪里、指纹是什么」——
// 在做规则调优时，这是第一个要看的东西。
func runRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("rules-dir", os.Getenv(config.EnvRulesDir), "外部规则目录（可选）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	rs, err := rules.Load(rules.Options{Dir: *dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bannerd: 规则加载失败: %v\n", err)
		return 1
	}

	fmt.Printf("source=%s  packs=%d  rules=%d  sha256=%s\n\n",
		rs.Source(), len(rs.Packs()), rs.Count(), rs.SHA256())
	for _, p := range rs.Packs() {
		fmt.Printf("%-10s %-16s %-8s %s\n", p.Pack, p.File, p.Origin, p.Description)
	}
	fmt.Println()
	for _, r := range rs.Rules() {
		fmt.Printf("  %-34s %-14s spec=%-3d origin=%s\n", r.ID, r.ProtocolName(), r.Specificity, r.Origin())
	}
	return 0
}

// runHealthcheck 是给容器用的探针。
//
// 它对 /health 发一个真实请求，并把 200 当作健康的唯一标准 ——
// 服务端的 /health 会实时跑一遍识别探针，因此「HTTP 200」在这里
// 等价于「识别引擎此刻确实还能正确工作」。
func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	url := fs.String("url", "http://127.0.0.1:8080/health", "健康检查地址")
	timeout := fs.Duration("timeout", 2*time.Second, "请求超时")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: 请求 %s 失败: %v\n", *url, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unhealthy: HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	fmt.Printf("healthy: %s\n", strings.TrimSpace(string(body)))
	return 0
}

func newLogger(level, format string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv}

	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	// 日志一律写 stdout：容器里 stdout 才是采集器的入口，
	// 写文件会跟 read_only 根文件系统直接冲突。
	return slog.New(h)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func usage(w io.Writer) {
	fmt.Fprint(w, `bannerd —— Banner 指纹识别服务端

用法:
  bannerd [选项]                 启动 HTTP 服务
  bannerd healthcheck [选项]     对 /health 发一次请求，按退出码表达健康与否
  bannerd rules [选项]           打印当前生效的规则清单
  bannerd version                打印版本
  bannerd help                   打印本帮助

服务选项:
  -addr string              监听地址（默认 "0.0.0.0:8080"，env BANNERD_LISTEN）
  -rules-dir string         外部规则目录；留空只用编进二进制的内置规则（env BANNERD_RULES_DIR）
  -log-level string         debug|info|warn|error（默认 info，env BANNERD_LOG_LEVEL）
  -log-format string        text|json（默认 text，env BANNERD_LOG_FORMAT）
  -debug                    默认开启 ?debug=1 诊断负载（env BANNERD_DEBUG）
  -max-body-bytes int       单个请求体上限（默认 16777216）
  -read-timeout duration    读超时（默认 15s）
  -write-timeout duration   写超时（默认 60s）
  -idle-timeout duration    keep-alive 空闲超时（默认 60s）
  -shutdown-timeout duration 优雅停机排空时间（默认 10s）

接口:
  POST /fingerprint   批量识别。请求体 [{"ip","port","banner"}] 或 {"items":[...]}，
                      响应为裸数组 [{"ip","port","protocol","product","version","os_hint","confidence"}]。
                      加 ?debug=1 时每条结果附带命中规则与候选列表。
  GET  /health        健康检查。实时跑探针 banner 过一遍识别引擎，规则被改坏返回 503。

示例:
  bannerd -addr :8080
  curl -s -X POST localhost:8080/fingerprint -d @testdata/sample_input.json
  bannerd healthcheck --url http://127.0.0.1:8080/health
`)
}
