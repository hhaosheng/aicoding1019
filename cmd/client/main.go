// Command bannerctl 是 Banner 指纹识别系统的客户端。
//
// 它做三件事：读本地 JSON → 分批发给服务端 → 把结果排成人能看的样子。
//
// 为什么是真·分批并发而不是一次性 POST 整个文件：真实扫描数据动辄几十万条，
// 单请求既会撞上服务端的体积上限，也会把失败代价放大到「全丢」。
// 分批之后失败被限制在一批之内，且并发让吞吐不再受单连接 RTT 支配。
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/aicoding1019/bannerd/internal/api"
	"github.com/aicoding1019/bannerd/internal/config"
	"github.com/aicoding1019/bannerd/internal/engine"
)

// 由 Dockerfile 的 -ldflags "-X main.version=... -X main.gitSHA=..." 注入。
var (
	version = "dev"
	gitSHA  = "unknown"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "-version", "--version":
			fmt.Printf("bannerctl %s (git %s, built with %s)\n", version, gitSHA, runtime.Version())
			return 0
		case "help", "-h", "--help":
			usage(os.Stdout)
			return 0
		}
	}

	cfg, err := config.ParseClient(args, usage)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(os.Stdout)
			return 0
		}
		fmt.Fprintf(os.Stderr, "bannerctl: %v\n\n", err)
		usage(os.Stderr)
		return 2
	}

	items, err := readItems(cfg.Input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bannerctl: %v\n", err)
		return 1
	}
	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, "bannerctl: 输入里没有任何记录")
		return 1
	}

	start := time.Now()
	results, err := recognize(cfg, items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bannerctl: %v\n", err)
		return 1
	}
	elapsed := time.Since(start)

	if err := render(os.Stdout, cfg.Format, results); err != nil {
		fmt.Fprintf(os.Stderr, "bannerctl: 输出失败: %v\n", err)
		return 1
	}

	identified, unknown := 0, 0
	for _, r := range results {
		if r.IsUnknown() {
			unknown++
		} else {
			identified++
		}
	}

	// 统计写 stderr：这样 `bannerctl --format json | jq` 拿到的
	// 仍然是干净的 JSON，而人在终端上照样看得到汇总。
	fmt.Fprintf(os.Stderr, "\n共 %d 条  |  已识别 %d  |  unknown %d  |  耗时 %s  |  服务端 %s\n",
		len(results), identified, unknown, elapsed.Round(time.Millisecond), cfg.ServerURL)

	if cfg.Strict && unknown > 0 {
		// unknown 本身不是错误（任务明确说「认不出来算 unknown 不算错」），
		// 但 CI 里往往想断言「这批数据必须全部认出来」。--strict 把这件事
		// 变成一个显式的、默认关闭的选择，而不是悄悄改变默认语义。
		fmt.Fprintf(os.Stderr, "bannerctl: --strict 生效：存在 %d 条 unknown\n", unknown)
		return 2
	}
	return 0
}

// readItems 读取并解析输入文件。
func readItems(path string) ([]engine.Item, error) {
	var (
		body []byte
		err  error
	)
	if path == "-" {
		if body, err = io.ReadAll(io.LimitReader(os.Stdin, 256<<20)); err != nil {
			return nil, fmt.Errorf("读取标准输入失败: %w", err)
		}
	} else {
		if body, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("读取输入文件失败: %w", err)
		}
	}
	// 复用服务端的解析逻辑：请求形态只有一个定义，客户端与服务端
	// 不可能因为「各自实现了一遍」而漂移。
	items, err := api.DecodeItems(body)
	if err != nil {
		return nil, fmt.Errorf("解析输入失败: %w", err)
	}
	return items, nil
}

// batch 是待发送的一段记录。
type batch struct {
	start, end int
}

// recognize 分批并发提交，并把结果按**输入顺序**回填。
func recognize(cfg config.Client, items []engine.Item) ([]engine.Result, error) {
	batches := make([]batch, 0, len(items)/cfg.BatchSize+1)
	for i := 0; i < len(items); i += cfg.BatchSize {
		end := i + cfg.BatchSize
		if end > len(items) {
			end = len(items)
		}
		batches = append(batches, batch{start: i, end: end})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make([]engine.Result, len(items))
	client := &http.Client{Timeout: cfg.Timeout}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	sem := make(chan struct{}, cfg.Concurrency)

	for _, b := range batches {
		wg.Add(1)
		sem <- struct{}{}
		go func(b batch) {
			defer wg.Done()
			defer func() { <-sem }()

			got, err := postBatch(ctx, client, cfg, items[b.start:b.end])

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					// 第一批失败就让其余批次尽快收敛，不必等它们把
					// 几百 MB 数据全发完才报错。
					cancel()
				}
				return
			}
			copy(results[b.start:b.end], got)
		}(b)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

func postBatch(ctx context.Context, client *http.Client, cfg config.Client, items []engine.Item) ([]engine.Result, error) {
	body, err := json.Marshal(api.Request{Items: items})
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	url := cfg.ServerURL + "/fingerprint"
	if cfg.Debug {
		url += "?debug=1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bannerctl/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s 失败: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("服务端返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out []engine.Result
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("解析服务端响应失败: %w", err)
	}
	if len(out) != len(items) {
		// 条数不匹配必须报错而不是「静默截断」：
		// 一份对不上号的识别报告比没有报告更危险。
		return nil, fmt.Errorf("响应条数不匹配：请求 %d 条，返回 %d 条", len(items), len(out))
	}
	return out, nil
}

// ---------------------------------------------------------------- 输出

func render(w io.Writer, format string, results []engine.Result) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "csv":
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"ip", "port", "protocol", "product", "version", "os_hint", "confidence"}); err != nil {
			return err
		}
		for _, r := range results {
			if err := cw.Write([]string{
				r.IP,
				fmt.Sprintf("%d", r.Port),
				r.Protocol,
				r.Product,
				r.Version,
				r.OSHint,
				fmt.Sprintf("%.2f", r.Confidence),
			}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		return renderTable(w, results)
	}
}

func renderTable(w io.Writer, results []engine.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	fmt.Fprintln(tw, "──\t────\t────────\t───────\t───────\t───────\t──────────")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, dash(r.Product), dash(r.Version), dash(r.OSHint), r.Confidence)
	}
	return tw.Flush()
}

// dash 把空字段显示成 "-"：表格里空白和「这一列被跳过了」长得一样，
// 明确写出来才读得懂。
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func usage(w io.Writer) {
	fmt.Fprint(w, `bannerctl —— Banner 指纹识别客户端

用法:
  bannerctl --input <文件> [选项]
  bannerctl version
  bannerctl help

选项:
  -input string        待识别的 JSON 文件；用 - 从标准输入读取（必填）
  -server string       服务端地址（默认 "http://127.0.0.1:8080"，env BANNERD_SERVER_URL）
  -format string       输出格式：table|json|csv（默认 table）
  -batch-size int      每批发送的记录数（默认 500）
  -concurrency int     并发批次数（默认 4）
  -timeout duration    单次请求超时（默认 60s）
  -debug               请求服务端返回诊断负载（命中规则与候选列表）
  -strict              只要存在 unknown 就以退出码 2 结束

输入格式（两种都接受）:
  [{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
  {"items":[{"ip":"1.2.3.4","port":22,"banner":"..."}]}

  二进制 banner 用 banner_b64 传 base64，可避免 JSON 转义问题。
  含字面量 \x00 的文本同样能直接解析 —— 客户端会先把非法 JSON 转义修补掉。

示例:
  bannerctl --input testdata/sample_input.json
  bannerctl --input testdata/sample_input.json --format json > out.json
  bannerctl --input testdata/sample_input.json --strict
  cat scan.json | bannerctl --input -
`)
}
