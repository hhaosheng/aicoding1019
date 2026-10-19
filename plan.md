# Banner 指纹识别系统 — 开发计划（plan.md）

> 目标：用 Golang 实现一个 Banner 指纹识别系统，接收批量网络扫描原始数据（ip / port / banner），
> 识别协议、软件与版本，以 **client + server** 架构、**Docker Compose 一键启动** 的方式交付。
>
> 文档状态：**待评审**。评审通过后按第 11 节里程碑实施。

---

## 1. 需求分析与验收要点

### 1.1 功能性需求（硬性）

| 编号 | 需求 | 落地判定方式 |
|---|---|---|
| F1 | server 提供 `POST /fingerprint`（批量识别） | 提交样例输入，返回逐条识别结果 |
| F2 | server 提供 `GET /health`（健康检查） | 200 + 结构化健康体；规则异常时返回 503 |
| F3 | client 是独立程序：读本地 JSON → 发 server → 展示结果 | 独立二进制 / 独立镜像，`-input` 指定文件 |
| F4 | 结果字段固定为 `ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence` | JSON 键名与示例逐字对齐 |
| F5 | `confidence` ∈ [0, 1] | 评分模型钳制，2 位小数 |
| F6 | 认不出统一返回 `protocol: "unknown"`，**不允许报错崩溃** | 单元测试覆盖空/二进制/超长/乱码 banner，服务始终 200 |
| F7 | 至少正确识别 SSH、HTTP（nginx / Apache / Jetty）、MySQL、Redis、FTP | 20 条自测数据全部命中预期 |
| F8 | Docker Compose 一键启动 | `docker compose up -d` 后服务 healthy，一条命令完成端到端验证 |

### 1.2 非功能性需求 — 映射到评估者的 5 个考察点

评估点不是清单，但要能被"看得见"，所以每条都要有一个**可检查的物证**：

| 考察点 | 设计决策 | 物证 |
|---|---|---|
| **容器间访问方式收敛** | 只暴露一个内部 bridge 网络 `backend`，且 `internal: true`（无出网、无宿主发布）；server **不发布任何宿主端口**，client 通过 compose 服务名 `http://server:8080` 访问；需要宿主调试时用独立的 `docker-compose.expose.yaml` 显式叠加 | `docker compose config` 中 server 无 `ports:`；`docker network inspect` 显示 internal |
| **启动依赖有真实健康检测** | `client` 用 `depends_on: {server: {condition: service_healthy}}`；server 的 healthcheck 不只看进程活着，而是执行 `/health` 的**引擎自检**（用内置样例 banner 跑一遍识别并断言结果），规则加载失败/自检不过 → 503 → 容器 unhealthy | `docker compose ps` 的 health 列；故意破坏一条规则可复现 unhealthy |
| **镜像体现编译打包理解** | 多阶段构建：`src`（清单 + `vendor/` 分区 COPY，改代码不失效依赖层）→ `test`（构建期跑 `go vet` + 单测）→ `build`（`CGO_ENABLED=0` 静态编译、`-trimpath -buildvcs=false`、`-ldflags="-s -w -X ..."` 注入版本）→ **`scratch`** 空镜像；`vendor/` + `GOTOOLCHAIN=local` 让**整条构建链零网络依赖**；数字 UID `65532:65532`；`.dockerignore` 收敛上下文 | Dockerfile 阶段结构；`docker image inspect` 的 Size / User；二进制 `-version` 输出；**断网可构建** |
| **容器运行权限收紧** | `read_only: true` + `tmpfs: /tmp`，`cap_drop: [ALL]`，`security_opt: [no-new-privileges:true]`，非 root 数字 UID，`pids_limit`、CPU/内存限额、日志轮转、`stop_grace_period` 配合 SIGTERM 优雅退出 | `docker inspect` 的 `HostConfig.ReadonlyRootfs / CapDrop / SecurityOpt / PidsLimit` |
| **识别规则与程序代码解耦** | 规则是 `rules/*.yaml` 数据文件，**不是 Go 代码**；`go:embed` 内置默认包保证空镜像可跑，同时支持 `-rules-dir` 挂载外部目录**覆盖/扩展**；规则热加载（mtime 轮询 + 原子替换），改规则不用重新编译镜像 | compose 里 `./rules:/etc/bannerd/rules:ro`？——见下注；改 YAML 后重启/热加载即生效 |

> **关于规则目录挂载的取舍**：挂载会让"空镜像自带规则"这一能力被掩盖，且削弱镜像自包含性。
> **决策**：默认**不挂载**，规则用 `go:embed` 编进二进制（镜像自包含、可复现）；
> 在 `docker-compose.expose.yaml`（或 README 记录的覆盖片段）中提供 `-v ./rules:/etc/bannerd/rules:ro`
> 的可选挂载，用于演示"改规则不重新编译"。两种能力都有物证，且默认形态最干净。

### 1.3 样例数据的能力要求（识别深度）

自测输入共 20 条，覆盖 6 类必答协议 + 5 类边角情况，**系统的识别深度至少要吃下这些**：

| # | 输入 banner（要点） | 期望输出要点 | 考察的能力 |
|---|---|---|---|
| 1 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` | SSH / OpenSSH / 8.9p1 / Ubuntu / 0.95 | 版本串含补丁后缀 `p1`；OS 从 `Ubuntu-3` 抽取 |
| 2 | `HTTP/1.1 200 OK\r\nServer: nginx/1.24.0` | HTTP / nginx / 1.24.0 / "" / 0.90 | 多行文本 + 指定字段抽取 |
| 3 | `Server: Apache/2.4.57` | HTTP / Apache / 2.4.57 / 0.90 | 同族多产品区分 |
| 4 | `J\x00\x00\x00\n8.0.32\x00` | MySQL / MySQL / 8.0.32 / 0.90 | **二进制协议**：定长头 + 协议版本字节 + NUL 结尾版本串 |
| 5 | `-ERR wrong number of arguments for 'get' command` | Redis / Redis / "" / 0.70 | 无版本；靠 Redis 内联回复语法识别 |
| 6 | `220 ProFTPD 1.3.7 Server (ProFTPD)` | FTP / ProFTPD / 1.3.7 / 0.90 | 状态码 220 前缀 + 产品名 |
| 7 | `HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51` | HTTP / Jetty / 9.4.51 / **0.85** | **同族不同置信度**，需数据驱动而非硬编码 |
| 8 | `SSH-2.0-OpenSSH_9.3 Debian-1` | SSH / OpenSSH / 9.3 / Debian | OS 映射表可扩展 |
| 9 | `Server: nginx/1.18.0 (Ubuntu)` | nginx / 1.18.0 / Ubuntu | 版本后带 OS 括号 |
| 10 | `Server: Apache/2.4.41 (Ubuntu)` | Apache / 2.4.41 / Ubuntu | 同上 |
| 11 | `J\x00\x00\x00\n5.7.42\x00` | MySQL / 5.7.42 | 跨大版本 |
| 12 | `+PONG` | Redis / "" / 0.70 | 极短 banner |
| 13 | `220 (vsFTPd 3.0.5)` | FTP / vsftpd / 3.0.5 | 产品名带括号、大小写混乱 |
| 14 | `Server: nginx/1.25.3` @ **8443** | nginx / 1.25.3 | **端口只是弱先验，非 80 也要认** |
| 15 | `SSH-1.99-OpenSSH_4.3` | SSH / OpenSSH / 4.3 | 老旧 `1.99` 兼容标记 |
| 16 | `\x16\x03\x01\x00\xa5\x01\x00\x00\xa1` | TLS / "" / 0.60 | **纯二进制 TLS 记录头**，非文本协议 |
| 17 | `Server: Microsoft-IIS/10.0` | Microsoft-IIS / 10.0 / **Windows** | OS 由产品**推断**（规则内声明） |
| 18 | `-NOAUTH Authentication required.` | Redis / "" / 0.70 | Redis 第二种错误回复 |
| 19 | `220 Welcome to Pure-FTPd` | FTP / Pure-FTPd / "" | 有产品无版本 |
| 20 | `QUIT\r\n` @ 12345 | **unknown** / "" / 0.00 | 真正认不出时必须优雅降级 |

**两个隐藏陷阱**（必须在设计层面解决，不是实现细节）：

- **陷阱 A：`\x00` 是字面量还是真实字节？**
  任务样例里 JSON 写的是 `\x00`，而 `\x` **不是合法 JSON 转义**。真实文件可能是两种形态：
  (a) `"J\\x00\\x00..."` — banner 字符串里就是 `\`、`x`、`0`、`0` 四个字符；
  (b) `"J\u0000\u0000..."` — 真正的 NUL 字节。
  → 设计：**双模解码 + 双遍匹配**。banner 先按"转义文本"尽力还原（`\xNN`/`\r`/`\n`/`\t`/`\\`/`\0`），
  规则在**解码后**的形态上匹配；若全部落空，再用**原始**形态重跑一遍。另外接受 `banner_b64` 字段承载精确字节。
- **陷阱 B：文本 banner 里的 `\r\n` 可能也是字面量**，同上由双模解码统一处理。

---

## 2. 系统架构设计

### 2.1 总体结构

```
  宿主机 / 评审脚本                  docker compose 网络 backend (internal: true)
 ┌──────────────────┐          ┌─────────────────────────────────────────────────┐
 │ testdata/        │  :ro     │                                                 │
 │  sample_input.json├─────────►│  [client]  bannerctl                            │
 └──────────────────┘  挂载     │   · 读本地 JSON / stdin                          │
                                │   · 分片(batch) + 重试退避 + 超时                 │
 ┌──────────────────┐          │   · 输出 table / json / csv                      │
 │ rules/  (可选)    │  :ro     │         │                                        │
 └────────┬─────────┘          │         │ POST /fingerprint                      │
          │ 覆盖/扩展            │         ▼                                        │
          │                     │  [server] bannerd  :8080 (仅网络内可达，不发布端口) │
          │                     │   · HTTP API + 中间件(recover/限流/限体/日志/超时) │
          └────────────────────►│   · 识别引擎(流水线) ◄── ruleset(embed + 外部目录) │
                                │   · 健康自检 GET /health                          │
                                │                                                 │
                                │   两者均: scratch 镜像 / 非 root 65532 / 只读根   │
                                │           cap_drop ALL / no-new-privileges       │
                                └─────────────────────────────────────────────────┘
```

**关键收敛点**：容器之间只有一条网络路径 —— `client --(backend, 服务名 DNS)--> server:8080`。
server 不发布宿主端口、网络 `internal: true` 无出网，攻击面与依赖关系都被收成一条线。

### 2.2 组件职责

| 组件 | 路径 | 职责 |
|---|---|---|
| server 入口 | `cmd/server/main.go` | 解析配置、加载规则、装配 HTTP、优雅退出、`healthcheck` 子命令 |
| client 入口 | `cmd/client/main.go` | 读文件、校验、分片、调用、渲染、退出码 |
| API 层 | `internal/api/` | 路由、DTO、中间件、错误码、请求 ID |
| 识别引擎 | `internal/engine/` | 流水线编排、候选打分、消歧、结果组装 |
| Banner 预处理 | `internal/banner/` | 双模转义解码、UTF-8 净化、按行切分、二进制探测 |
| 规则系统 | `internal/rules/` | YAML schema、嵌入与外部目录合并、编译校验、热加载 |
| 健康自检 | `internal/health/` | 用内置探针 banner 跑引擎并断言，产出 `/health` 体 |
| 规则数据 | `rules/*.yaml` | **纯数据**：协议识别 + 产品/版本/OS 抽取 + 评分参数 |
| 接口契约 | `api/openapi.yaml` | OpenAPI 3.1 描述 |

### 2.3 依赖策略与环境基线

**只引入一个第三方依赖：`gopkg.in/yaml.v3` v3.0.1**（解析规则文件），并 **`go mod vendor` 提交
`vendor/` 目录**。其余全部标准库：`net/http`、`encoding/json`、`log/slog`、`regexp`、`embed`、
`flag`、`context`、`sync`、`os/signal`。

**为什么 vendor 化**：vendor 化之后 `go build -mod=vendor` **既不需要模块缓存也不需要网络**，
Docker 构建因此是真正可复现、可离线的。本机 `proxy.golang.org` 不可达（`GOPROXY` 已指向可达的
`https://goproxy.cn`），但构建不应依赖任何外网可用性 —— 唯一的那一个依赖直接进仓库。

**Go 版本基线 = 1.22，不是 1.26**：

- 本机 Go 是 1.26.5，但**本地 Docker 里唯一可用的构建镜像是 `golang:1.22-alpine3.20`**
  （实测 `go version go1.22.12 linux/amd64`）。把 `go.mod` 定为 `go 1.22` 后，
  宿主机 1.26.5 与容器 1.22.12 **都能编译**，而构建路径做到**零镜像拉取**。
- 所用能力全部落在 1.22 及以下，不存在版本倒挂：

| 能力 | 最低版本 | 用途 |
|---|---|---|
| `http.ServeMux` 的方法+路径模式（`"POST /fingerprint"`） | 1.22 | 三条路由，免引 Web 框架 |
| `log/slog` | 1.21 | 结构化日志（JSON handler） |
| `min` / `max` 内建函数 | 1.21 | 分数钳制 |
| `atomic.Pointer[T]` | 1.19 | 规则集原子热替换 |
| `errors.Join` | 1.20 | 规则校验聚合报错 |
| `strings.ToValidUTF8` | 1.13 | banner 净化 |
| `embed` / `testing.F` | 1.16 / 1.18 | 规则内置 / fuzz 测试 |

- 升级路径留好：`GO_VERSION`、`GO_FLAVOR` 都是 build arg，将来切 1.26 只改 `go.mod` 与构建参数，业务代码不动。

- 不引 Web 框架 → 路由只有 3 条，`http.ServeMux` 足够，少一层黑盒。
- 不引 fsnotify → 热加载用 mtime 轮询（5s），零依赖且在容器内可靠。
- 不引 YAML 之外的序列化库 → 输入输出统一 `encoding/json`。
- 不引 testing 框架 → 标准库 `testing` + `testdata` 黄金文件。
- **RE2 正则天然无回溯**，不存在 ReDoS；代价是不支持反向引用与环视，规则 DSL 的语法子集在加载期用
  `regexp.Compile` 校验，非法规则带 `rule_id` 快速失败（fail fast），不允许静默跳过。

---

## 3. 接口契约

### 3.1 `POST /fingerprint`

**请求体接受两种形态**（样例输入是裸数组，必须兼容；信封形态便于批量元信息）：

```jsonc
// 形态 A —— 裸数组（与任务样例一致，主要兼容路径）
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip": "1.2.3.7", "port": 3306, "banner": "J\x00\x00\x00\n8.0.32\x00"}
]

// 形态 B —— 信封
{"items": [ {"ip": "...", "port": 22, "banner": "..."} ]}
```

单条 item 字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ip` | string | 建议 | 原样回显，不做校验（可能是域名或空串） |
| `port` | int | 建议 | 0–65535；仅作**弱先验**参与加权，绝不作为识别前提 |
| `banner` | string | 二选一 | 文本形态，自动做转义还原（见陷阱 A） |
| `banner_b64` | string | 二选一 | base64 原始字节，用于精确二进制输入；与 `banner` 同时存在时以 `banner_b64` 为准 |

**响应体默认是裸数组**（严格对齐任务示例），可用 `?envelope=1` 切换为带元信息的信封：

```jsonc
// 默认（= 任务示例形态）
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}
]

// ?envelope=1
{
  "results": [ /* 同上，字段顺序与输入顺序严格一致，1:1 不增不减 */ ],
  "summary": {"total":20,"recognized":19,"unknown":1,"elapsed_ms":4,"ruleset":{"pack_version":"1.0.0","sha256":"ab12…","count":42}}
}
```

**协议正确性约束（很重要）**：

- `results` 与 `items` **严格 1:1 且顺序一致**；任何单条失败都不允许丢条目。
- 单条数据非法（缺 `ip`、`port` 越界、banner 为空）→ 该条返回 `protocol:"unknown"`、`confidence:0`，
  整体仍是 **200**，只为该条输出 `protocol:"unknown"`。
- 只有**请求体本身**不是合法 JSON / 超限时才返回 4xx。

**错误码**：

| 状态 | 场景 | 响应体 |
|---|---|---|
| 200 | 正常（含全部条目都 unknown） | 结果数组 |
| 400 | 请求体不是合法 JSON、或 items 不是数组 | `{"error":{"code":"invalid_request","message":"..."}}` |
| 413 | 超过 `max_body_bytes`（默认 8 MiB）或 `max_items`（默认 10000） | `{"error":{"code":"payload_too_large",...}}` |
| 415 | Content-Type 非 `application/json` | `{"error":{"code":"unsupported_media_type",...}}` |
| 500 | 未预期 panic（被 recover 兜住） | `{"error":{"code":"internal","request_id":"..."}}` |
| 503 | `/health` 自检失败 | 见 3.2 |

### 3.2 `GET /health` —— 真实自检，不是"进程活着"

```jsonc
{
  "status": "ok",                       // ok | degraded -> 200 / 503
  "version": "0.1.0",
  "git_sha": "9f2c1ab",
  "uptime_s": 42,
  "ruleset": {
    "pack_version": "1.0.0",
    "sha256": "ab12cd34…",              // 规则包内容哈希：能证明"当前生效的是哪一版规则"
    "rules": 42,
    "source": "embedded+external",      // embedded | external | embedded+external
    "loaded_at": "2026-10-19T07:00:00Z"
  },
  "checks": {
    "engine_selftest": {"ok": true, "cases": 6, "failed": []},
    "ruleset_loaded":  {"ok": true}
  }
}
```

**自检逻辑**：内置 6 条探针 banner（覆盖 SSH/HTTP/MySQL/Redis/FTP/TLS），每次请求实时跑一遍引擎，
断言 `protocol`/`product`/`version` 与期望一致；任一条不符 → `status:"degraded"` + **503**，
并在 `failed` 里给出 `{probe, want, got}`。这让"规则被改坏"这件事能被 healthcheck 直接抓到，
而不是等业务请求出错。`docker compose` 的 healthcheck 正是打这个端点。

---

## 4. 识别引擎设计

### 4.1 流水线

```
 原始 banner (string | b64)
   │
   ├─(1) 解码   internal/banner.Decode     双模转义还原 / base64 / 原始字节保留
   ├─(2) 净化   internal/banner.Sanitize   strings.ToValidUTF8(b, "\uFFFD")，剔除 CR 噪声，限长 64 KiB
   ├─(3) 角色判定  binary-probe：是否含 NUL / 不可打印字节 → 走二进制协议规则
   │
   ├─(4) 候选匹配  for each rule: 全部 match 命中 AND 至少一个 match_any 命中
   │                → 产出 match{rule, captures{product,version,os_hint}, shape}
   │
   ├─(5) 打分     score(match) = clamp(Σ 权重, floor, ceiling/ceiling_no_version)
   │
   ├─(6) 消歧     取最高分；平分时按 (规则特异性 specificity 降序 → 声明顺序)
   │
   └─(7) 降级     无候选 → protocol:"unknown", product/version/os_hint:"", confidence:0.00
                  双遍：上述全落空时，用"未解码的原始形态"重跑 (4)~(6)
```

**关键点**：引擎对单条 item 包 `recover()`，任何一条数据触发 panic 只会让该条降级为 `unknown`，
不会中断整批，也不会 500 —— 直接对应 F6「不允许因为认不出来就报错崩掉」。

### 4.2 置信度评分模型（数据驱动，可复现）

权重写在规则的 `score` 块里，引擎不硬编码任何产品名：

```yaml
score:
  protocol: 0.60            # 协议签名命中（默认值，规则可覆盖）
  product: 0.15             # 抽到 product
  version: 0.10             # 抽到 version
  os_hint: 0.05             # 抽到 os_hint
  port_agree: 0.05          # 观测端口落在规则声明的 ports 内（弱先验，最多 +0.05）
  ceiling: 0.95             # 全量命中上限
  ceiling_no_version: 0.75  # 未抽到 version 时的上限（默认）
```

`confidence = round(min(ceiling_applicable, 0.60 + Σbonus), 2)`，再钳制到 `[0,1]`。

**用 7 条样例输出反推验证（这是模型正确性的硬证据）**：

| # | banner 要点 | 计算 | 上限 | 结果 | 示例期望 |
|---|---|---|---|---|---|
| 1 | OpenSSH_8.9p1 Ubuntu-3 / :22 | .60+.15+.10+.05(os)+.05(port) | 0.95 | **0.95** | 0.95 ✅ |
| 2 | nginx/1.24.0 / :80 | .60+.15+.10+0+.05(port) | 0.95 | **0.90** | 0.90 ✅ |
| 3 | Apache/2.4.57 / :443 | .60+.15+.10+0+.05(port) | 0.95 | **0.90** | 0.90 ✅ |
| 4 | MySQL 8.0.32 / :3306 | .60+.15+.10+0+.05(port) | 0.90 | **0.90** | 0.90 ✅ |
| 5 | Redis `-ERR …` / :6379 | .60+.15+0+0+.05(port)=0.80 | 0.70 | **0.70** | 0.70 ✅ |
| 6 | ProFTPD 1.3.7 / :21 | .60+.15+.10+0+.05(port) | 0.95 | **0.90** | 0.90 ✅ |
| 7 | Jetty/9.4.51 / :8080 | .60+.15+.10+0+.05(port)=0.90 | **0.85** | **0.85** | 0.85 ✅ |

→ **7/7 精确复现**。其中两处差异完全由**规则数据**解释，而不是代码分支：

- Redis 拿 0.70：规则声明 `ceiling_no_version: 0.70` —— 一条内联错误回复可被伪造，诚实地上限更低。
- Jetty 拿 0.85（低于同族 nginx/Apache 的 0.90）：`http.jetty` 规则声明 `ceiling: 0.85`，
  因为 Jetty 允许应用覆盖 `Server` 头，版本信息可信度天然低一档。

**这正是"规则与代码解耦"的价值证明**：调置信度只需改 YAML，不碰一行 Go。

### 4.3 逐条推演（其余 13 条自测数据）

| # | 判定 | 预期输出 | 置信度 |
|---|---|---|---|
| 8 | `ssh.openssh` + Debian | SSH / OpenSSH / 9.3 / Debian | 0.95 |
| 9 | `http.nginx` + `(Ubuntu)` | HTTP / nginx / 1.18.0 / Ubuntu | 0.95 |
| 10 | `http.apache` + `(Ubuntu)` | HTTP / Apache / 2.4.41 / Ubuntu | 0.95 |
| 11 | `mysql.greeting` | MySQL / MySQL / 5.7.42 / "" | 0.90 |
| 12 | `redis.inline_reply` (`+PONG`) | Redis / Redis / "" / "" | 0.70 |
| 13 | `ftp.vsftpd` | FTP / vsftpd / 3.0.5 / "" | 0.90 |
| 14 | `http.nginx` @8443 | HTTP / nginx / 1.25.3 / "" | 0.90 |
| 15 | `ssh.openssh`（1.99 兼容标记） | SSH / OpenSSH / 4.3 / "" | 0.90 |
| 16 | `tls.record_clienthello` | **TLS** / "" / "" / "" | 0.60 |
| 17 | `http.iis`（规则内静态 os_hint） | HTTP / Microsoft-IIS / 10.0 / **Windows** | 0.95 |
| 18 | `redis.inline_reply` (`-NOAUTH`) | Redis / Redis / "" / "" | 0.70 |
| 19 | `ftp.pureftpd` | FTP / Pure-FTPd / "" / "" | 0.75 |
| 20 | 无任何规则命中 | **unknown** / "" / "" / "" | 0.00 |

> **第 16 条的设计取舍（写入 README）**：TLS 记录头里的 `03 01` 是 **record version**，
> 在 ClientHello 上几乎恒为 legacy 值（1.0/1.2），**不代表协商出的版本**。
> 因此只报 `protocol:"TLS"`，`version` 留空（0.60），而不是编一个 `1.0` 出来 —— 宁可低分也不给假信息。
> 原始字节留在 `?debug=1` 的附加字段里供人工研判。

### 4.4 有序性、并发与确定性

- 输出顺序 = 输入顺序：结果切片按下标预分配，worker 只写 `results[i]`，无锁、无重排。
- 并发：`min(GOMAXPROCS, 8)` 个 worker 处理 items；`-workers` 可调。
- **确定性**：同一输入必然产出同一输出（无 map 迭代序、无时间依赖、分数纯函数）。
  这是能被黄金文件测试断言的前提。

---

## 5. 规则 DSL 设计（解耦的核心）

### 5.1 文件组织

```
rules/
├── _pack.yaml     # 包元信息: version, description（参与 sha256 计算）
├── ssh.yaml
├── http.yaml
├── ftp.yaml
├── mysql.yaml
├── redis.yaml
├── tls.yaml
├── mail.yaml      # SMTP/POP3/IMAP —— 超出必答范围，低成本增加深度
└── generic.yaml   # 兜底与关键词弱规则
```

### 5.2 Schema（代表性片段）

```yaml
# rules/ssh.yaml
version: 1
pack: ssh
protocol: SSH                     # 本文件规则的默认协议
ports: [22, 2222, 2022]           # 协议级端口先验，规则可继承
rules:
  - id: ssh.openssh
    description: "OpenSSH identification string (RFC 4253 §4.2)"
    specificity: 100              # 消歧用：越具体越高
    match:                        # ALL 必须命中
      - regex: '^SSH-(?P<sshver>[0-9]\.[0-9]{2})-(?P<product>OpenSSH)[-_](?P<version>[0-9][0-9A-Za-z.\-]*)'
    product: OpenSSH              # 规范化产品名（不依赖 banner 原样大小写）
    os_hint:                      # 命中即取 value，可多条
      - {regex: '(?i)\bubuntu\b', value: Ubuntu}
      - {regex: '(?i)\bdebian\b', value: Debian}
      - {regex: '(?i)\bfreebsd\b', value: FreeBSD}
    score: {ceiling: 0.95, ceiling_no_version: 0.80}

  - id: ssh.generic
    specificity: 50
    match:
      - regex: '^SSH-(?P<sshver>[0-9]\.[0-9]{2})-(?P<product>[^\s_-]+)'
    score: {ceiling: 0.85, ceiling_no_version: 0.75}
```

```yaml
# rules/http.yaml （节选）
version: 1
pack: http
protocol: HTTP
ports: [80, 81, 88, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443]
rules:
  - id: http.nginx
    specificity: 90
    match:
      - regex: '(?mi)^Server:\s*nginx/(?P<version>[0-9][0-9A-Za-z.\-]*)'
    product: nginx
    os_hint:
      - {regex: '(?i)\(ubuntu\)', value: Ubuntu}
      - {regex: '(?i)\(debian\)', value: Debian}
    score: {ceiling: 0.95, ceiling_no_version: 0.75}

  - id: http.jetty
    specificity: 90
    match:
      - regex: '(?mi)^Server:\s*Jetty(?:\((?P<extra>[^)]*)\))?/(?P<version>[0-9][0-9A-Za-z.\-]*)'
    product: Jetty
    score: {ceiling: 0.85, ceiling_no_version: 0.70}   # 应用可覆盖 Server 头 → 可信度低一档

  - id: http.iis
    specificity: 90
    match:
      - regex: '(?mi)^Server:\s*Microsoft-IIS/(?P<version>[0-9][0-9.]*)'
    product: Microsoft-IIS
    os_hint: [{value: Windows}]                        # 静态推断：IIS 只跑 Windows
    score: {ceiling: 0.95, ceiling_no_version: 0.75}

  - id: http.generic
    specificity: 10
    match: [{regex: '^HTTP/[0-9]\.[0-9] \d{3}\b'}]
    score: {ceiling: 0.60, ceiling_no_version: 0.60}
```

```yaml
# rules/mysql.yaml —— 二进制协议，两条规则体现"位置严格 vs 宽松"
version: 1
pack: mysql
protocol: MySQL
ports: [3306, 3307, 13306]
rules:
  - id: mysql.greeting
    specificity: 95
    # 3B 包长 + 1B 序号 + 0x0A 协议版本 + NUL 结尾版本串
    match:
      - regex: '(?s)^.{4}\x0a(?P<version>[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-]*)'
    product: MySQL
    score: {ceiling: 0.90, ceiling_no_version: 0.70}

  - id: mysql.greeting_loose        # banner 可能被截断，放宽位置
    specificity: 70
    match:
      - regex: '(?s)\x0a(?P<version>[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-]*)\x00'
    product: MySQL
    score: {ceiling: 0.85, ceiling_no_version: 0.65}

  - id: mysql.mariadb
    specificity: 96
    match:
      - regex: '(?s)\x0a(?P<version>[0-9][0-9A-Za-z.\-]*-MariaDB[0-9A-Za-z.\-]*)'
    product: MariaDB
```

```yaml
# rules/redis.yaml
version: 1
pack: redis
protocol: Redis
ports: [6379, 6380, 16379]
rules:
  - id: redis.inline_reply
    specificity: 80
    match:
      - regex: '^(?:\+PONG\b|\+OK\b|-ERR\b|-NOAUTH\b|-WRONGTYPE\b|-MOVED\b|-LOADING\b|\*[0-9]+\r?\n|:[0-9]+\r?\n)'
    product: Redis
    # 内联回复可被伪造，且无版本可交叉验证 → 上限压到 0.70
    score: {ceiling: 0.70, ceiling_no_version: 0.70}
```

```yaml
# rules/ftp.yaml （节选）
version: 1
pack: ftp
protocol: FTP
ports: [21, 2121, 8021]
rules:
  - id: ftp.proftpd
    specificity: 90
    match:
      - regex: '^220[\s\-]'
      - regex: '(?i)\bProFTPD[ /](?P<version>[0-9][0-9A-Za-z.\-]*)'
    product: ProFTPD
  - id: ftp.pureftpd
    specificity: 88
    match:
      - regex: '^220[\s\-]'
      - regex: '(?i)\bPure-?FTPd\b(?:\s+(?P<version>[0-9][0-9A-Za-z.\-]*))?'
    product: Pure-FTPd
    score: {ceiling: 0.95, ceiling_no_version: 0.75}
  - id: ftp.generic
    specificity: 10
    match: [{regex: '^220[\s\-]'}]
    score: {ceiling: 0.60, ceiling_no_version: 0.60}
```

```yaml
# rules/tls.yaml
version: 1
pack: tls
protocol: TLS
rules:
  - id: tls.handshake_clienthello
    specificity: 85
    match:
      - regex: '^\x16\x03[\x00-\x04][\x00-\xff]{2}[\x01\x02]'
    score: {ceiling: 0.60, ceiling_no_version: 0.60}   # 只认到 record 层，版本留空
  - id: tls.record
    specificity: 40
    match:
      - regex: '^\x16\x03[\x00-\x04]'
    score: {ceiling: 0.55, ceiling_no_version: 0.55}
```

### 5.3 加载与合并语义

1. **基线**：`go:embed rules/*.yaml` → 空镜像自带完整规则包，镜像自包含、可复现。
2. **覆盖**：`-rules-dir /etc/bannerd/rules`（可选挂载）。**同名文件整文件替换**内置同名 pack；
   目录中新增的 pack 追加。不做"逐规则合并"——整文件替换语义简单、可预测、易解释。
3. **校验**：加载期用 `regexp.Compile` 编译每条正则、校验 `id` 唯一、`protocol` 非空、
   `score` 各值 ∈ [0,1] 且 `ceiling_no_version ≤ ceiling`。任一失败 → **启动失败并打印 `rule_id`**（fail fast），
   绝不允许静默跳过坏规则（否则"规则写错"会表现成"识别率莫名下降"，极难排查）。
4. **热加载**：`-rules-watch`（默认 true，仅当指定了 `-rules-dir`）。每 5s 比对文件列表 + mtime + size，
   变化则全量重载、编译成功后**原子替换** `atomic.Pointer[RuleSet]`；编译失败则**保留旧规则集**并
   在日志与 `/health` 里报 `degraded`，服务不中断。
5. **可观测**：`/health` 返回规则包 `sha256` + `count`，任何时刻能确认"生效的是哪一版规则"。

---

## 6. 生产级部署设计

### 6.1 镜像（多阶段 + scratch）

> **刻意不写 `# syntax=docker/dockerfile:1.7`**：那行会强制拉取一个 frontend 镜像，破坏"零拉取"。
> `RUN --mount=type=cache` 由 BuildKit 内置 frontend 直接支持，无需该指令。

```dockerfile
# 基线镜像刻意选本地已有的 tag —— 实测 go1.22.12 linux/amd64 可用。
# 配合 scratch 运行时 + vendor/ 依赖，整条构建链 **零镜像拉取、零网络依赖**。
ARG GO_VERSION=1.22
ARG GO_FLAVOR=alpine3.20

# ---- 源码层：依赖清单 + vendor + 源码分区 COPY，改代码不失效依赖层 ----
FROM golang:${GO_VERSION}-${GO_FLAVOR} AS src
WORKDIR /src
# GOTOOLCHAIN=local 关键：禁止 Go 因 go.mod 版本去联网下载新工具链
ENV GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/
COPY rules/ rules/
COPY testdata/ testdata/

# ---- 校验层：vet + 单测（CI 用 `docker build --target test .`）----
FROM src AS test
RUN --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./...

# ---- 编译层：静态、可复现、版本注入 ----
FROM src AS build
ARG VERSION=dev
ARG GIT_SHA=unknown
RUN --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w -X main.version=${VERSION} -X main.gitSHA=${GIT_SHA}" && \
    GOOS=linux go build -mod=vendor -trimpath -buildvcs=false -tags 'netgo,osusergo' \
      -ldflags "$LDFLAGS" -o /out/bannerd  ./cmd/server && \
    GOOS=linux go build -mod=vendor -trimpath -buildvcs=false -tags 'netgo,osusergo' \
      -ldflags "$LDFLAGS" -o /out/bannerctl ./cmd/client

# ---- 运行时：scratch，数字 UID，无 shell / 无包管理器 / 无 libc ----
FROM scratch AS server
COPY --from=build /out/bannerd /usr/local/bin/bannerd
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bannerd"]

FROM scratch AS client
COPY --from=build /out/bannerctl /usr/local/bin/bannerctl
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/bannerctl"]
```

**为什么是 `scratch`（写进 README 的取舍说明）**：

- `CGO_ENABLED=0` + `netgo,osusergo` 后二进制**完全静态**，不依赖 glibc，`scratch` 直接可跑。
- 无 shell / 无 `apk` / 无 `apt` / 无 CA 库 → 即使应用被攻破也**没有可用的工具链打点**，攻击面最小。
- 本系统服务端**不发起任何出网 TLS 连接**（client→server 走 compose 内网明文 HTTP），
  因此不需要 CA 根证书；若将来要出网 HTTPS，只需 `COPY --from=build /etc/ssl/certs/ca-certificates.crt`。
- 无 tzdata → 日志统一 UTC / RFC3339，不调用 `time.LoadLocation`。
- 体积 ~6 MB（对比 alpine 基础 ~12 MB、distroless/static ~2 MB+应用）。
- **副作用**：`scratch` 里没有 `curl`/`wget`，所以 **healthcheck 必须用二进制自身** ——
  这恰好是 `bannerd healthcheck` 子命令存在的原因（见 6.3），也是"编译打包理解"的直接体现。

### 6.2 `docker-compose.yaml`（默认形态：锁死）

```yaml
name: bannerd

x-hardening: &hardening
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  tmpfs: ["/tmp:rw,noexec,nosuid,size=16m"]
  restart: unless-stopped
  logging:
    driver: json-file
    options: {max-size: "10m", max-file: "3"}

services:
  server:
    build:
      context: .
      target: server
      args:
        VERSION: "0.1.0"
        GIT_SHA: "${GIT_SHA:-unknown}"
    image: bannerd-server:0.1.0
    <<: *hardening
    user: "65532:65532"
    environment:
      BANNERD_LISTEN: "0.0.0.0:8080"
      BANNERD_LOG_FORMAT: json
      BANNERD_LOG_LEVEL: info
      # 注意：默认不挂载规则目录 —— 规则已 embed 进镜像
    networks: [backend]
    # 刻意不写 ports: —— 不向宿主机发布任何端口
    pids_limit: 128
    stop_grace_period: 10s          # 配合 SIGTERM 优雅退出，等在途请求排空
    healthcheck:
      test: ["CMD", "/usr/local/bin/bannerd", "healthcheck", "--url", "http://127.0.0.1:8080/health"]
      interval: 5s
      timeout: 2s
      retries: 5
      start_period: 3s
    deploy:
      resources:
        limits: {cpus: "1.0", memory: 128M}

  client:
    build:
      context: .
      target: client
      args: {VERSION: "0.1.0"}
    image: bannerd-client:0.1.0
    <<: *hardening
    restart: "no"                   # 一次性批处理程序，不重启
    user: "65532:65532"
    profiles: ["run"]               # 默认 compose up 不起它；用 compose run 触发
    depends_on:
      server:
        condition: service_healthy  # ← 真实健康检测驱动的启动依赖
    environment:
      BANNERD_SERVER_URL: "http://server:8080"   # 服务名 DNS，唯一的跨容器路径
    volumes:
      - ./testdata:/data:ro          # 输入只读挂载
    networks: [backend]
    command: ["-input", "/data/sample_input.json", "-format", "table"]
    pids_limit: 64
    deploy:
      resources:
        limits: {cpus: "0.5", memory: 64M}

networks:
  backend:
    driver: bridge
    internal: true    # ← 无出网、无宿主发布：容器间访问收敛为唯一一条路径
```

**配套 `docker-compose.expose.yaml`（仅供本地人工验证，显式叠加）**：

```yaml
# 用法: docker compose -f docker-compose.yaml -f docker-compose.expose.yaml up -d
services:
  server:
    networks: [backend, hostaccess]
    ports: ["127.0.0.1:8080:8080"]   # 只绑回环，不暴露到局域网
networks:
  hostaccess: {driver: bridge}
```

### 6.3 健康检测与启动依赖（"真实"体现在哪）

| 层次 | 做法 | 为什么算"真实" |
|---|---|---|
| server healthcheck | `bannerd healthcheck --url .../health`，退出码 0/1 | scratch 无 curl，只能由程序自证；且打的是**应用语义端点**而非 TCP 探活 |
| `/health` 内容 | 实时跑 6 条探针 banner 过一遍引擎并断言结果 | 检测的是**识别能力**，不是"进程还在"；规则被改坏 → 503 → unhealthy |
| client 启动 | `depends_on.condition: service_healthy` | 依赖的是**健康**而非仅"已启动"，避免 client 抢跑拿到连接拒绝 |
| 就绪 vs 存活 | `/health`（存活+自检）；预留 `/readyz` 口径（规则集已加载） | 语义分离，便于后续接 k8s |

### 6.4 权限收紧清单（对照 `docker inspect` 可验）

| 项 | 配置 | 效果 |
|---|---|---|
| 用户 | `USER 65532:65532` + compose `user:` | 非 root，无 `passwd` 依赖 |
| 根文件系统 | `read_only: true` | 容器不可写自身文件系统 |
| 可写区 | `tmpfs /tmp:noexec,nosuid` | 唯一可写点，且不可执行 |
| Capabilities | `cap_drop: [ALL]` | 丢弃全部 Linux capability（监听 8080 无需 `CAP_NET_BIND_SERVICE`） |
| 提权 | `no-new-privileges:true` | 禁止 setuid 提权 |
| 进程数 | `pids_limit: 128 / 64` | 限制 fork 炸弹 |
| 资源 | CPU / 内存 limits | 限制资源耗尽 |
| 日志 | `json-file` + `max-size/max-file` | 防止日志写爆宿主磁盘 |
| 网络 | `internal: true`、无端口发布 | 无出网、无外部入口 |
| 停机 | `stop_grace_period` + SIGTERM 处理 | 优雅排空，不是硬杀 |

---

## 7. 目录结构

```
D:\code\aicoding1019\
├── plan.md                     # 本文档
├── README.md                   # 快速开始 / 验证步骤 / 设计取舍说明
├── go.mod  go.sum              # go 1.22
├── vendor/                     # 唯一依赖 yaml.v3 已 vendor → 构建零网络
├── Makefile                    # build / test / lint / up / verify / down
├── Dockerfile                  # src → test → build → server / client (scratch)
├── .dockerignore               # 必须保留 vendor/（否则离线构建失效）
├── docker-compose.yaml         # 默认：锁定形态
├── docker-compose.expose.yaml  # 可选：仅本地人工验证
├── .dockerignore  .gitignore
├── api/
│   └── openapi.yaml
├── cmd/
│   ├── server/main.go          # 含 healthcheck 子命令
│   └── client/main.go
├── internal/
│   ├── api/        server.go handlers.go middleware.go dto.go errors.go
│   ├── engine/     engine.go pipeline.go score.go dedupe.go engine_test.go
│   ├── rules/      schema.go loader.go embed.go validate.go watch.go
│   ├── banner/     decode.go sanitize.go probe.go decode_test.go
│   ├── health/     selftest.go
│   ├── config/     config.go
│   └── version/    version.go
├── rules/          _pack.yaml ssh.yaml http.yaml ftp.yaml mysql.yaml
│                   redis.yaml tls.yaml mail.yaml generic.yaml
├── testdata/
│   ├── sample_input.json       # 20 条自测输入（与任务一致）
│   ├── sample_expected.json    # 20 条黄金输出
│   ├── edge_cases.json         # 空/乱码/超长/纯 NUL/未闭合转义
│   └── probes.json             # /health 自检探针
└── scripts/
    ├── verify.ps1              # Windows 一键端到端验收
    └── verify.sh               # Linux/macOS 等价
```

---

## 8. Client 设计

| 能力 | 设计 |
|---|---|
| 输入 | `-input <file>`，支持 `-` 读 stdin；也接受裸数组或 `{"items":[...]}` 两种形态 |
| 目标 | `-server`，默认取 `BANNERD_SERVER_URL`，再退回 `http://127.0.0.1:8080` |
| 分片 | `-batch-size`（默认 500），大文件拆多次请求，逐片输出进度 |
| 重试 | 仅对**幂等可重试**错误（连接拒绝 / 超时 / 429 / 5xx）做指数退避 + 抖动，`-retries`（默认 3）、`-timeout`（默认 10s）、尊重 `context` 取消 |
| 传输 | 单例 `http.Client` 复用连接（`MaxIdleConnsPerHost` 调优），`Content-Type: application/json` |
| 输出 | `-format table`（默认，对齐表格）/ `json`（**裸数组，与 server 默认响应同形**）/ `csv`；`-color auto|always|never` |
| 退出码 | `0` 成功；`1` 用法/输入文件错误；`2` 传输或服务端错误；`-strict` 时出现 `unknown` 也返回 `3` |
| 二进制安全 | 读入后若 banner 含非 UTF-8/含 NUL 字节，自动改走 `banner_b64` 字段，确保字节无损 |

输出示例（table）：

```
IP           PORT   PROTOCOL  PRODUCT       VERSION   OS_HINT   CONFIDENCE
1.2.3.4      22     SSH       OpenSSH       8.9p1     Ubuntu    0.95
1.2.3.5      80     HTTP      nginx         1.24.0              0.90
...
1.2.3.23     12345  unknown                                      0.00
---
total=20 recognized=19 unknown=1 elapsed=6ms
```

---

## 9. 测试与验收策略

### 9.1 测试分层

| 层 | 内容 | 位置 |
|---|---|---|
| 单元 | 转义双模解码、UTF-8 净化、截断边界、评分公式、消歧平局、规则校验拒绝非法正则 | `internal/*/\*_test.go` |
| 黄金文件 | 20 条自测数据 + 全部 edge case 逐条比对 `sample_expected.json` | `internal/engine` |
| 集成 | `httptest` 起真实 handler，覆盖 200/400/413/415/500、裸数组与信封、万条并发、优雅停机 | `internal/api` |
| 契约 | 用 `?envelope=1` 与默认形态各断言一次；字段名/类型严格校验 | `internal/api` |
| 容器 | `docker compose build` → `up -d --wait` → `compose run --rm client` → 比对预期 → 检查硬化项 | `scripts/verify.*` |

### 9.2 边界用例（必须全部通过且**服务不崩**）

`banner=""` / 纯 NUL / 纯不可打印字节 / 64 KiB+ 超长 / 未闭合的 `\x` 转义 / 非法 UTF-8 /
超长单行 / 混合 CRLF/LF/CR / 只有换行 / items 为空数组 / 10000 条超限 / port = 0 与 65536 /
banner 与 banner_b64 同时给出 / 极端正则输入（如 1 MiB 全 `A`）验证 RE2 线性时间。

### 9.3 一键验收（`scripts/verify.ps1`）

```
[1/7] go vet ./... && go test ./... -count=1
[2/7] docker compose build
[3/7] docker compose up -d --wait                 # 等 healthy，失败即非 0 退出
[4/7] docker compose run --rm client -format json > out.json   # 端到端
[5/7] 比对 out.json 与 testdata/sample_expected.json（字段级）
[6/7] 检查硬化：ReadonlyRootfs / CapDrop=ALL / SecurityOpt / PidsLimit / User=65532
      检查收敛：server 无端口发布；network internal=true
      检查依赖：client depends_on 为 service_healthy
[7/7] docker compose down -v
```

`Makefile` 提供 `make verify` 作为等价入口；README 把 `verify` 作为唯一推荐验证方式。

### 9.4 验收清单（对照需求逐条勾选）

- [ ] F1 `POST /fingerprint` 批量识别可用，裸数组与信封入参都通
- [ ] F2 `GET /health` 返回结构化健康体，自检失败时 503
- [ ] F3 client 独立程序：读本地 JSON → 请求 server → 表格/JSON 展示
- [ ] F4 七个字段名与示例逐字一致，顺序 1:1
- [ ] F5 confidence ∈ [0,1]，2 位小数
- [ ] F6 unknown 优雅降级；全部边界用例不崩、不 5xx
- [ ] F7 SSH / HTTP(nginx·Apache·Jetty) / MySQL / Redis / FTP 全部命中；20 条样例中 19 条识别、1 条 unknown
- [ ] F8 `docker compose up -d --wait` 一键起，`compose run --rm client` 一键验
- [ ] 评估点 1：容器间访问收敛为唯一内网路径，无发布端口、无出网
- [ ] 评估点 2：healthcheck 打应用语义端点 + 引擎自检；client 依赖 `service_healthy`
- [ ] 评估点 3：多阶段 + 静态编译 + scratch + 版本注入 + `.dockerignore` + 构建期跑测试
- [ ] 评估点 4：非 root / 只读根 / cap_drop ALL / no-new-privileges / 限额 / 日志轮转
- [ ] 评估点 5：规则为 YAML 数据，可覆盖可热加载，调置信度不动代码

---

## 10. 风险与决策记录

### 10.1 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| **Docker Hub 直连不可达**（实测 `registry-1.docker.io` 超时，`docker manifest inspect` 三个 tag 全部失败） | 任何需要拉镜像的步骤都可能卡住 | **已消除**：构建镜像用**本地已缓存**的 `golang:1.22-alpine3.20`，运行时用 `scratch`（保留名，无需拉取），依赖走 `vendor/`。整条构建链零拉取 |
| `proxy.golang.org` 不可达（实测超时） | `go mod download` 失败 | **已消除**：`vendor/` 提交进仓库 + `GOTOOLCHAIN=local` + `-mod=vendor`；`GOPROXY` 已指向实测可达的 `https://goproxy.cn` 作兜底 |
| `# syntax=docker/dockerfile:1.7` 会强制拉 frontend 镜像 | 构建卡住 | Dockerfile 刻意不写该指令；`--mount=type=cache` 由 BuildKit 内置 frontend 支持 |
| `--mount=type=cache` 在过老 BuildKit 上不可用 | 构建报错 | 该 flag 只影响构建速度、不影响正确性；报错则删掉 `--mount` 即可（README 记录一行处置） |
| 评审脚本直接 POST 裸数组 | 400 导致误判 | 入参**双形态**兼容（3.1 形态 A/B） |
| `\x00` 语义二义 | MySQL 样例识别失败 | 双模解码 + 双遍匹配 + `banner_b64` 通道 |
| `internal: true` 让评审者无法从宿主 curl | 验感受阻 | 提供 `docker-compose.expose.yaml`；README 把 `compose run --rm client` 作为主验证路径 |
| 默认响应加信封被判"与示例不符" | 形态不匹配 | 默认**裸数组**，信封为 `?envelope=1` 选项 |
| RE2 语法子集限制（无反向引用/环视） | 规则写法受限 | 加载期校验并给出 `rule_id` + 原因；DSL 文档写明支持子集 |
| scratch 无 tzdata / CA | 时间与出网 TLS 受限 | 日志统一 UTC；不出网；README 记录补 CA 的一行做法 |
| 规则写错表现为"识别率下降" | 难排查 | fail fast + `/health` 暴露规则包 sha256 与自检失败明细 |

### 10.2 决策记录（ADR 摘要）

- **ADR-001 不引 Web 框架**：路由仅 3 条，`net/http` + 自写中间件链，依赖面最小、行为完全可控。
- **ADR-002 规则用 YAML + embed + 外部目录**：解耦是评估点，改规则不动代码、不重编译镜像；
  整文件替换而非逐规则合并，语义简单可预测。
- **ADR-003 默认裸数组响应**：严格对齐任务示例；元信息走 `?envelope=1`，不牺牲兼容性换信息量。
- **ADR-004 运行时用 `scratch`**：静态二进制下 `scratch` 攻击面最小、体积最小；
  代价是 healthcheck 必须自证，反而更贴合"真实健康检测"的考察点。
- **ADR-005 compose 默认不发布端口 + `internal: true`**：把"收敛"做成默认而非可选；
  人工验证通过显式 override 叠加。
- **ADR-006 置信度按规则数据加权**：评分权重与上限写在 YAML，7 条示例输出被精确复现，
  证明模型而非硬编码。
- **ADR-007 二进制协议按字节解析**：MySQL/TLS 用 `\xNN` 正则按字节匹配，
  不用"把 NUL 替换成空格"这类会丢信息的预处理。
- **ADR-008 vendor 化依赖 + Go 基线 1.22 + 不写 `# syntax=`**：这三条合起来让
  `docker compose build` **完全不依赖外网与镜像源**（实测本机 Docker Hub 直连超时、
  `proxy.golang.org` 超时）。代价是 `go.mod` 版本低于本机 Go，收益是构建可复现、可离线、可评测。
- **ADR-009 规则整文件替换而非逐规则合并**：外部规则目录中同名 pack 整文件覆盖内置，
  语义可预测、易于解释；避免"半覆盖"导致的隐性行为差异。

---

## 11. 实施里程碑

| 阶段 | 交付物 | 完成判据 |
|---|---|---|
| **M0 脚手架** | go.mod、目录骨架、Makefile、`.dockerignore`/`.gitignore`、CI 可跑的 `go vet` | `go build ./...` 通过 |
| **M1 规则系统** | `internal/rules/*`、`rules/_pack.yaml` | 加载/校验/覆盖/热加载单测通过；坏规则启动即报 `rule_id` |
| **M2 Banner 预处理** | `internal/banner/*` | 双模解码、二进制探测、净化边界单测通过 |
| **M3 引擎 + 评分** | `internal/engine/*` | 评分公式单测复现第 4.2 节 7/7 表 |
| **M4 规则包** | `rules/*.yaml` 全套 | 20 条样例中 19 条识别、第 20 条 unknown |
| **M5 server** | `cmd/server`、`internal/api`、`internal/health` | 端点/错误码/优雅停机集成测试通过；`/health` 自检有效 |
| **M6 client** | `cmd/client` | 分片/重试/三种输出/退出码覆盖 |
| **M7 容器化** | `Dockerfile`、`docker-compose*.yaml` | `up -d --wait` healthy；`compose run client` 结果与黄金文件一致 |
| **M8 验收与文档** | `scripts/verify.*`、`README.md`、`api/openapi.yaml` | `make verify` 全绿；README 可被第三方照做复现 |

**关键路径**：M1 → M2 → M3 → M4 是识别能力主线（也是评分与解耦两个评估点的载体）；
M7 依赖 M5/M6 可运行但设计已在第 6 节冻结，可与 M3~M6 并行准备。

---

## 12. 待确认事项（请评审确认）

1. **响应默认形态**：采用**裸数组**（严格对齐示例）+ `?envelope=1` 可选信封 —— 是否认可？
2. **规则目录默认不挂载**：默认规则 embed 进镜像（自包含、可复现），挂载作为可选演示 —— 是否认可？
3. **TLS（样例第 16 条）**：识别为 `protocol:"TLS"`、`version` 留空、置信度 0.60，
   而不是编造一个 record version —— 是否认可？
4. **client 在 compose 中的默认触发方式**：`profiles: ["run"]`，即 `up -d` 只起 server，
   用 `docker compose run --rm client` 跑批处理 —— 是否认可？
5. **第三方依赖仅 `gopkg.in/yaml.v3` v3.0.1 一个，并 `vendor/` 进仓库** —— 是否认可？
6. **Go 版本基线定 1.22**（`go.mod` 写 `go 1.22`，构建镜像用本地已有的 `golang:1.22-alpine3.20`），
   换取「构建零网络依赖、零镜像拉取」；宿主机 Go 1.26.5 同样能编译 —— 是否认可？
   若坚持跟随 1.26，前提是先能拉到 `golang:1.26-*` 镜像（当前网络下不可验证）。
