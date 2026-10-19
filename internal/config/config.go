// Package config 集中解析命令行参数与环境变量。
//
// 单一来源原则：默认值只在这里出现一次，cmd/ 下的两个 main 不各自硬编码。
// 优先级为 **命令行 > 环境变量 > 内置默认值** —— 这是容器场景的通行约定：
// 镜像里写死环境变量表达「部署形态」，命令行表达「这一次的特殊调整」。
package config

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// 环境变量名。容器编排只应该通过它们来配置镜像，不需要知道任何命令行细节。
const (
	EnvListen    = "BANNERD_LISTEN"
	EnvRulesDir  = "BANNERD_RULES_DIR"
	EnvLogLevel  = "BANNERD_LOG_LEVEL"
	EnvLogFormat = "BANNERD_LOG_FORMAT"
	EnvServerURL = "BANNERD_SERVER_URL"
	EnvDebug     = "BANNERD_DEBUG"
)

// 默认值。
const (
	DefaultListen   = "0.0.0.0:8080"
	DefaultServer   = "http://127.0.0.1:8080"
	DefaultLogLevel = "info"
	// DefaultLogFormat 默认用 text：本地跑时肉眼可读；容器里由
	// BANNERD_LOG_FORMAT=json 覆盖成结构化日志，交给采集器。
	DefaultLogFormat = "text"

	// DefaultMaxBodyBytes 限制单个请求体大小。
	//
	// 16 MiB 是权衡结果：20 条自测数据只有几 KB，而真实扫描批次动辄上万条。
	// 上限存在的意义是防止一个超大请求把 128M 内存限额的容器打爆 ——
	// 超过上限时返回 413，让调用方改用分批发送，而不是让服务 OOM。
	DefaultMaxBodyBytes = 16 << 20
)

// Server 是服务端配置。
type Server struct {
	Addr            string
	RulesDir        string
	LogLevel        string
	LogFormat       string
	Debug           bool
	MaxBodyBytes    int64
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Client 是客户端配置。
type Client struct {
	ServerURL   string
	Input       string
	Format      string
	Timeout     time.Duration
	BatchSize   int
	Concurrency int
	Debug       bool
	Strict      bool
}

// Usage 由调用方注入，避免本包直接往 os.Stderr 写。
type Usage func(w io.Writer)

// ParseServer 解析服务端参数。args 不含子命令名。
func ParseServer(args []string, usage Usage) (Server, error) {
	fs := flag.NewFlagSet("bannerd", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // 错误信息由调用方统一输出，避免重复

	var (
		addr     = fs.String("addr", envOr(EnvListen, DefaultListen), "HTTP 监听地址，如 :8080（env "+EnvListen+"）")
		rulesDir = fs.String("rules-dir", os.Getenv(EnvRulesDir), "外部规则目录；留空则只用编译进二进制的内置规则（env "+EnvRulesDir+"）")
		logLevel = fs.String("log-level", envOr(EnvLogLevel, DefaultLogLevel), "日志级别：debug|info|warn|error（env "+EnvLogLevel+"）")
		logFmt   = fs.String("log-format", envOr(EnvLogFormat, DefaultLogFormat), "日志格式：text|json（env "+EnvLogFormat+"）")
		debug    = fs.Bool("debug", envBool(EnvDebug), "默认打开 ?debug=1 的诊断负载（env "+EnvDebug+"）")
		maxBody  = fs.Int64("max-body-bytes", DefaultMaxBodyBytes, "单个请求体上限（字节）")
		readTO   = fs.Duration("read-timeout", 15*time.Second, "读取请求的超时")
		writeTO  = fs.Duration("write-timeout", 60*time.Second, "写响应的超时")
		idleTO   = fs.Duration("idle-timeout", 60*time.Second, "keep-alive 空闲超时")
		stopTO   = fs.Duration("shutdown-timeout", 10*time.Second, "收到 SIGTERM 后排空在途请求的时间")
	)

	if err := fs.Parse(args); err != nil {
		return Server{}, err
	}
	if fs.NArg() > 0 {
		return Server{}, fmt.Errorf("无法识别的多余参数: %s", strings.Join(fs.Args(), " "))
	}

	cfg := Server{
		Addr:            strings.TrimSpace(*addr),
		RulesDir:        strings.TrimSpace(*rulesDir),
		LogLevel:        strings.ToLower(strings.TrimSpace(*logLevel)),
		LogFormat:       strings.ToLower(strings.TrimSpace(*logFmt)),
		Debug:           *debug,
		MaxBodyBytes:    *maxBody,
		ReadTimeout:     *readTO,
		WriteTimeout:    *writeTO,
		IdleTimeout:     *idleTO,
		ShutdownTimeout: *stopTO,
	}
	if cfg.Addr == "" {
		return Server{}, fmt.Errorf("-addr 不能为空")
	}
	if cfg.MaxBodyBytes <= 0 {
		return Server{}, fmt.Errorf("-max-body-bytes 必须为正数，当前为 %d", cfg.MaxBodyBytes)
	}
	switch cfg.LogFormat {
	case "text", "json":
	default:
		return Server{}, fmt.Errorf("-log-format 只能是 text 或 json，当前为 %q", cfg.LogFormat)
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return Server{}, fmt.Errorf("-log-level 只能是 debug|info|warn|error，当前为 %q", cfg.LogLevel)
	}
	return cfg, nil
}

// ParseClient 解析客户端参数。args 不含子命令名。
func ParseClient(args []string, usage Usage) (Client, error) {
	fs := flag.NewFlagSet("bannerctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		server = fs.String("server", envOr(EnvServerURL, DefaultServer), "服务端地址（env "+EnvServerURL+"）")
		input  = fs.String("input", "", "待识别的 JSON 文件路径；用 - 表示从标准输入读取")
		format = fs.String("format", "table", "输出格式：table|json|csv")
		to     = fs.Duration("timeout", 60*time.Second, "单次请求超时")
		batch  = fs.Int("batch-size", 500, "每批发送的记录数")
		conc   = fs.Int("concurrency", 4, "并发发送的批次数")
		debug  = fs.Bool("debug", false, "请求服务端返回诊断负载并打印")
		strict = fs.Bool("strict", false, "只要存在 unknown 就以退出码 2 结束（供 CI 断言用）")
	)

	if err := fs.Parse(args); err != nil {
		return Client{}, err
	}
	if fs.NArg() > 0 {
		return Client{}, fmt.Errorf("无法识别的多余参数: %s", strings.Join(fs.Args(), " "))
	}

	cfg := Client{
		ServerURL:   strings.TrimRight(strings.TrimSpace(*server), "/"),
		Input:       strings.TrimSpace(*input),
		Format:      strings.ToLower(strings.TrimSpace(*format)),
		Timeout:     *to,
		BatchSize:   *batch,
		Concurrency: *conc,
		Debug:       *debug,
		Strict:      *strict,
	}
	if cfg.ServerURL == "" {
		return Client{}, fmt.Errorf("-server 不能为空")
	}
	if !strings.HasPrefix(cfg.ServerURL, "http://") && !strings.HasPrefix(cfg.ServerURL, "https://") {
		// 顺手补全：容器里常写成 server:8080，省得每个人都被 URL 解析绊一次。
		cfg.ServerURL = "http://" + cfg.ServerURL
	}
	if cfg.Input == "" {
		return Client{}, fmt.Errorf("-input 必填（可以写 - 从标准输入读）")
	}
	switch cfg.Format {
	case "table", "json", "csv":
	default:
		return Client{}, fmt.Errorf("-format 只能是 table|json|csv，当前为 %q", cfg.Format)
	}
	if cfg.BatchSize <= 0 {
		return Client{}, fmt.Errorf("-batch-size 必须为正数，当前为 %d", cfg.BatchSize)
	}
	if cfg.Concurrency <= 0 {
		return Client{}, fmt.Errorf("-concurrency 必须为正数，当前为 %d", cfg.Concurrency)
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
