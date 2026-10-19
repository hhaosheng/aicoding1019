# Banner 指纹识别系统（bannerd + bannerctl）

接收批量网络扫描原始数据（`ip` / `port` / `banner`），识别出 **协议 / 产品 / 版本 / OS 提示** 与 **置信度**。
Go 实现，client + server 一对二进制，`docker compose up` 一键启动。

| 组件 | 二进制 | 职责 |
|---|---|---|
| server | `bannerd` | HTTP API（`POST /fingerprint`、`GET /health`）、识别引擎、启动期一次性加载规则集、优雅退出；另有 `healthcheck` 子命令供容器健康检测使用 |
| client | `bannerctl` | 读本地 JSON / stdin → 分片请求 server → 输出 `table` / `json` / `csv`，带重试与退出码 |
| 规则 | `rules/*.yaml` | **纯数据**：协议签名、产品/版本/OS 抽取、评分权重与上限 |

三条设计主张：

- **识别规则是数据，不是代码。** 调一个产品的置信度上限、加一种产品版本正则，都只改 YAML，不碰一行 Go，也不重编译镜像。
- **容器间只有一条路径。** 唯一网络 `backend`（`internal: true`），server 默认**不发布任何宿主端口**，client 只能走服务名 DNS `http://server:8080`。
- **健康检查真的在检查识别能力。** `/health` 每次调用都会把 6 条内置探针 banner 跑一遍识别引擎并断言结果，规则被改坏直接 503。

接口契约见 [`api/openapi.yaml`](api/openapi.yaml)，完整设计见 [`plan.md`](plan.md)。

---

## 能力与识别深度

对样例数据的前 7 条，期望输出（也就是"什么叫做对了"）：

| IP | PORT | PROTOCOL | PRODUCT | VERSION | OS_HINT | CONFIDENCE |
|---|---|---|---|---|---|---|
| 1.2.3.4 | 22 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 |
| 1.2.3.5 | 80 | HTTP | nginx | 1.24.0 | | 0.90 |
| 1.2.3.6 | 443 | HTTP | Apache | 2.4.57 | | 0.90 |
| 1.2.3.7 | 3306 | MySQL | MySQL | 8.0.32 | | 0.90 |
| 1.2.3.8 | 6379 | Redis | Redis | | | 0.70 |
| 1.2.3.9 | 21 | FTP | ProFTPD | 1.3.7 | | 0.90 |
| 1.2.3.10 | 8080 | HTTP | Jetty | 9.4.51 | | 0.85 |

覆盖面（20 条自测样例中 19 条识别、1 条按设计返回 `unknown`）：

- **文本协议**：SSH（含 `SSH-1.99` 老式兼容标记、`8.9p1` 补丁后缀、从 `Ubuntu-3` / `Debian-1` / `(Ubuntu)` 抽 OS）、HTTP（nginx / Apache / Jetty / Microsoft-IIS，含 `Server` 头分行、版本后带 OS 括号）、FTP（ProFTPD / vsftpd / Pure-FTPd，`220` 状态码前缀）、Redis（`+PONG` / `-ERR` / `-NOAUTH` 内联回复）。
- **二进制协议**：MySQL 握手包（3 字节包长 + 1 字节序号 + `0x0A` 协议版本 + NUL 结尾版本串）、TLS 记录头（`\x16\x03\x01...`）—— 按字节匹配，不做"把 NUL 换成空格"这类丢信息的预处理。
- **弱先验而非前提**：端口只参与加权，`Server: nginx/1.25.3` 落在 `8443` 上照样识别。
- **优雅降级**：空 banner、纯 NUL、非法 UTF-8、超长、未闭合 `\x` 转义、`QUIT\r\n` 这类认不出的输入一律 `protocol: "unknown"`，整体仍返回 **200**，不报错、不 500。

---

## 快速开始

前置：Docker + Compose v2。**构建与运行都不需要外网**（原理见下文「生产级部署说明」的第 3 点）。

### 一键启动并端到端跑一次

```bash
docker compose --profile run build   # 多阶段构建，零镜像拉取、零网络依赖
docker compose up -d --wait          # 只起 server；--wait 等到 healthcheck 真的通过
docker compose run --rm client       # 一次性批处理：读 testdata 样例 → 请求 server → 打印表格
```

`client` 服务在 `profiles: ["run"]` 里，所以：`up` 不会启动它（跑批处理用 `docker compose run --rm client`）；`build` 也默认跳过它，想一次把两个镜像都建出来要显式带上 `--profile run`（`make image` 就是这么做的）。`docker compose run` 在镜像缺失时会自己补建，所以上面三条命令照抄即可。

`client` 的默认输出（`-format table`）：

```text
IP        PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONFIDENCE
──        ────   ────────  ───────        ───────  ───────  ──────────
1.2.3.4   22     SSH       OpenSSH        8.9p1    Ubuntu   0.95
1.2.3.5   80     HTTP      nginx          1.24.0   -        0.90
1.2.3.6   443    HTTP      Apache         2.4.57   -        0.90
1.2.3.7   3306   MySQL     MySQL          8.0.32   -        0.90
1.2.3.8   6379   Redis     Redis          -        -        0.70
1.2.3.9   21     FTP       ProFTPD        1.3.7    -        0.90
1.2.3.10  8080   HTTP      Jetty          9.4.51   -        0.85
…（中间 12 行略）…
1.2.3.22  21     FTP       Pure-FTPd      -        -        0.75
1.2.3.23  12345  unknown   -              -        -        0.00

共 20 条  |  已识别 19  |  unknown 1  |  耗时 3ms  |  服务端 http://server:8080
```

两点值得注意：表格走 **stdout**，最后那行汇总走 **stderr** —— 所以 `bannerctl --format json | jq` 拿到的仍然是干净的 JSON，而人在终端上照样看得到汇总；空字段一律渲染成 `-`，不会让列错位。

### 看结果的其他方式

```bash
docker compose run --rm client -format json      # 裸数组，与 server 默认响应同形
docker compose run --rm client -format csv       # 逗号分隔
docker compose ps                                # 看 server 的 health 列
docker compose logs -f server                    # 结构化 JSON 日志
```

### 从宿主机人工戳一下（可选）

server 默认不发布宿主端口（刻意的，理由见下文「生产级部署说明」的第 1 点）。要本地 curl，显式叠加 override：

```bash
docker compose -f docker-compose.yaml -f docker-compose.expose.yaml up -d
curl -sS http://127.0.0.1:8080/health
```

`docker-compose.expose.yaml` 只绑定 `127.0.0.1:8080`，不会把端口暴露到局域网。

### 不用容器，本机直接跑

```bash
go run ./cmd/server --addr :8080 --rules-dir ./rules     # 规则来自外部目录
go run ./cmd/client -input testdata/sample_input.json -server http://127.0.0.1:8080
```

---

## 接口说明

### `POST /fingerprint` —— 批量识别

**请求体接受两种形态**（样例输入是裸数组，必须兼容；`{"items":[...]}` 对象包装便于带批量元信息）：

```jsonc
// 形态 A —— 裸数组
[ {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"} ]

// 形态 B —— 对象包装（只存在于**请求**侧，响应侧没有对称形态）
{ "items": [ {"ip": "1.2.3.4", "port": 22, "banner": "..."} ] }
```

请求 item 字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ip` | string | 是 | 原样回显，不做校验（可能是域名或空串） |
| `port` | int | 是 | 0–65535；仅作弱先验参与加权，绝不作为识别前提 |
| `banner` | string | 二选一 | 文本形态；`\xNN` / `\r` / `\n` / `\t` / `\\` / `\0` 会被尽力还原为真实字节后再匹配 |
| `banner_b64` | string | 二选一 | base64 原始字节，用于精确二进制输入；与 `banner` 同时给出时**以 `banner_b64` 为准** |

查询参数（**只有一个**）：

| 参数 | 说明 |
|---|---|
| `?debug=1` | 在结果项上附加诊断负载（命中规则、候选列表、banner 长度与转义标记等），供人工研判；这些字段不属于稳定契约。服务端 `-debug` / `BANNERD_DEBUG` 可把默认值打开 |

**响应体永远是裸数组**（严格对齐任务示例）；**全部元数据走响应头**：

| 响应头 | 说明 |
|---|---|
| `X-Request-Id` | 每个响应都有；与错误体里的 `request_id` 一致 |
| `X-Bannerd-Rules-Sha256` | 本次识别所用规则集的内容哈希 |
| `X-Bannerd-Items` | 结果条数（与请求条目 1:1 且顺序一致） |
| `X-Bannerd-Identified` | 识别出的条数 |
| `X-Bannerd-Unknown` | 降级为 `unknown` 的条数 |
| `X-Bannerd-Duration-Ms` | 本次批量识别的耗时（毫秒） |
| `X-Bannerd-Degraded` | **仅在自检探针有失败时出现**，值为失败条数；此时 `/fingerprint` **仍返回 200 与结果** |

```jsonc
[ {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95} ]
```

响应 item 字段（**严格这 7 个**，与请求 item **1:1 且顺序一致**，任何单条失败都不丢条目）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `ip` | string | 原样回显 |
| `port` | int | 原样回显 |
| `protocol` | string | 协议名；认不出为 `"unknown"` |
| `product` | string | 规范化的产品名（不依赖 banner 原样大小写）；未抽到为空串 |
| `version` | string | 版本串；未抽到为空串 |
| `os_hint` | string | OS 提示；未抽到为空串 |
| `confidence` | number | `0` ~ `1`，保留 2 位小数；`unknown` 恒为 `0` |

### `GET /health` —— 真实自检，不是"进程活着"

```jsonc
{
  "status": "ok",                       // ok | degraded → 200 / 503
  "version": "0.1.0",
  "git_sha": "9f2c1ab",
  "uptime_s": 42,
  "rules": {
    "source": "embedded",               // embedded | external | embedded+external
    "schema_version": 1,                // 规则文件 schema 版本（不是"包版本"，也不是规则条数）
    "packs": 9,                         // 规则包文件数
    "count": 47,                        // 规则条数
    "sha256": "c4f9122d…",              // 规则集内容哈希：能证明当前生效的是哪一版规则
    "loaded_at": "2026-10-19T07:38:21Z"
  },
  "probes": {
    "total": 6,
    "passed": 6,
    "failures": []                      // 每项为 {name, want, got}
  }
}
```

每次调用都实时跑 6 条内置探针 banner（覆盖 SSH / HTTP / MySQL / Redis / FTP）过一遍引擎，断言 `protocol` / `product` / `version`；任一条不符即 `status: "degraded"` + **HTTP 503**，并在 `probes.failures` 里给出 `{name, want, got}`（`got` 形如 `SSH/OpenSSH/8.9p1/Ubuntu/0.95`，`want` 形如 `SSH/OpenSSH/8.9p1/Ubuntu/>=0.95`）。

### 状态码

| 状态 | 场景 | 响应体 |
|---|---|---|
| 200 | 识别正常（含**全部条目都 unknown**）；`/health` 自检通过 | 结果数组 / 健康对象 |
| 400 | 请求体为空、不是合法 JSON，或不是「数组 / `{"items":[...]}` 对象」 | `{"error":{"code":"bad_json","message":"…","request_id":"…"}}` |
| 404 | 路径不存在 | `{"error":{"code":"not_found","message":"…","request_id":"…"}}` |
| 405 | 路径存在但方法不对（响应带 `Allow` 头） | `{"error":{"code":"method_not_allowed","message":"…","request_id":"…"}}` |
| 413 | 请求体超过 `max_body_bytes`（默认 16 MiB） | `{"error":{"code":"body_too_large","message":"…","request_id":"…"}}` |
| 500 | 未预期 panic（被中间件 recover 兜住） | `{"error":{"code":"internal_error","message":"…","request_id":"…"}}` |
| 503 | `/health` 自检失败（degraded）——**这一条只属于 `/health`** | 见上 |

错误体固定三字段 `{code, message, request_id}`，三者**全部必填**，`request_id` 与响应头 `X-Request-Id` 一致；`code` 的全部取值只有 `internal_error` / `method_not_allowed` / `not_found` / `body_too_large` / `bad_request` / `bad_json` 六个。

**没有 415。** 服务端刻意不校验 `Content-Type`：`curl -X POST -d @file` 默认发 `application/x-www-form-urlencoded`，强校验会让文档里"复制粘贴就能跑"的示例直接失败 —— 宁可在解析 JSON 时给出清晰的 `bad_json`。这是刻意的取舍，不是漏实现。

**`/fingerprint` 永不返回 503。** 挂载外部规则目录是本项目的卖点，而外部规则覆盖不全时内置探针必然失败；若因此让 `/fingerprint` 硬失败，"换个规则文件就能改识别能力"就变成"一换就报错"。健康与否是 `/health` 的职责，`/fingerprint` 最多加一个 `X-Bannerd-Degraded` 响应头。

**关键语义**：单条 item 数据非法（缺字段、`port` 越界、banner 为空）**不是错误**——该条降级为 `protocol:"unknown"`、`confidence:0`，整批仍然 200。只有"请求体本身"不合法或超限才 4xx。

### client CLI

| Flag | 默认 | 说明 |
|---|---|---|
| `-input <file>` | 必填 | 输入 JSON；`-` 表示读 stdin；两种请求形态都接受 |
| `-server <url>` | `$BANNERD_SERVER_URL` → `http://127.0.0.1:8080` | 目标 server |
| `-batch-size` | 500 | 大文件拆成多次请求，逐片输出进度 |
| `-format` | `table` | `table` / `json` / `csv`；`json` 输出裸数组，与 server 默认响应同形 |
| `-strict` | false | 出现 `unknown` 结果时以退出码 3 结束 |
| `-timeout` | 10s | 单次请求超时 |

传输层只对**幂等可重试**的失败（连接拒绝、超时、429、5xx）做指数退避 + 抖动重试，并尊重 `context` 取消。
若 banner 含 NUL 或非法 UTF-8，client 会自动改用 `banner_b64` 字段发送，保证字节无损。

退出码：

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 用法错误（参数拼错、取值非法） |
| 2 | 输入文件错误、传输失败或服务端错误 |
| 3 | 设置了 `-strict` 且结果中存在 `unknown` |

### server CLI

```bash
bannerd --addr :8080 --rules-dir ./rules     # 常规启动；--rules-dir 可选
bannerd healthcheck --url http://127.0.0.1:8080/health   # 容器 healthcheck 用；退出码 0/1
```

---

## 识别原理与置信度模型

### 流水线

```text
原始 banner (string | b64)
 │
 ├─(1) 解码     双模转义还原 / base64 / 原始字节保留
 ├─(2) 净化     ToValidUTF8、剔除 CR 噪声、限长 64 KiB
 ├─(3) 角色判定 含 NUL / 不可打印字节 → 走二进制协议规则
 ├─(4) 候选匹配 每条规则：全部 match 命中 AND 至少一个 match_any 命中 → 产出 captures
 ├─(5) 打分     clamp(Σ 权重, floor, ceiling / ceiling_no_version)
 ├─(6) 消歧     取最高分；平分时按 specificity 降序 → 声明顺序
 └─(7) 降级     无候选 → protocol:"unknown"、其余空、confidence 0.00
                双遍：上述全落空时，用「未解码的原始形态」重跑 (4)~(6)
```

引擎对单条 item 包 `recover()`：任何一条数据触发 panic 只会让该条降级为 `unknown`，不会中断整批、不会 500。
并发用 `min(GOMAXPROCS, 8)` 个 worker，结果切片按下标预分配、无锁、不重排；**同一输入必然产出同一输出**（无 map 迭代序、无时间依赖、分数是纯函数），这是黄金文件测试成立的前提。

### 置信度公式

```text
confidence = round( min(ceiling_applicable, protocol + Σ bonus), 2 )   再钳制到 [0, 1]
```

权重**全部声明在 YAML 里**，引擎不硬编码任何产品名：

| 权重项 | 默认值 | 含义 |
|---|---|---|
| `protocol` | 0.60 | 协议签名命中 |
| `product` | 0.15 | 抽到 `product` |
| `version` | 0.10 | 抽到 `version` |
| `os_hint` | 0.05 | 抽到 `os_hint` |
| `port_agree` | 0.05 | 观测端口落在规则声明的 `ports` 内（弱先验，最多 +0.05） |
| `ceiling` | 0.95 | 全量命中时的上限 |
| `ceiling_no_version` | 0.75 | 未抽到 `version` 时的上限 |

用上面 7 行输出反推验证（模型正确性的硬证据）：

| # | banner 要点 | 计算 | 生效上限 | 结果 |
|---|---|---|---|---|
| 1 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` / :22 | .60+.15+.10+.05(os)+.05(port) | 0.95 | **0.95** |
| 2 | `Server: nginx/1.24.0` / :80 | .60+.15+.10+0+.05(port) | 0.95 | **0.90** |
| 3 | `Server: Apache/2.4.57` / :443 | .60+.15+.10+0+.05(port) | 0.95 | **0.90** |
| 4 | MySQL `8.0.32` / :3306 | .60+.15+.10+0+.05(port) | 0.90 | **0.90** |
| 5 | Redis `-ERR …` / :6379 | .60+.15+0+0+.05(port) = 0.80 | **0.70** | **0.70** |
| 6 | `220 ProFTPD 1.3.7 …` / :21 | .60+.15+.10+0+.05(port) | 0.95 | **0.90** |
| 7 | `Server: Jetty/9.4.51` / :8080 | .60+.15+.10+0+.05(port) = 0.90 | **0.85** | **0.85** |

两个"看起来奇怪"的数字，完全由**规则数据**解释，而不是代码里的分支：

- **Redis 只有 0.70**：`redis.inline_reply` 把 `ceiling` 与 `ceiling_no_version` 都压到 `0.70`。一条内联错误回复（`-ERR …`、`+PONG`）是任何东西都能伪造的字符串，而且这条规则本身拿不到版本号，所以诚实地上限更低。
- **Jetty 只有 0.85**，低于同族的 nginx / Apache（0.90）：`http.jetty` 声明 `ceiling: 0.85`，因为 Jetty 允许**应用代码覆盖 `Server` 头**，它报出来的版本天然比 nginx 少一档可信度。

**这就是"规则与代码解耦"的价值证明**：想把 Jetty 提到 0.90，或者给某个新产品定一个上限，改的是 YAML 里的一行 `ceiling`，不是 Go 里的一个 `if`。

---

## 规则 DSL 与解耦

### 文件组织

```text
rules/
├── _pack.yaml     # 全局置信度权重基线（协议/产品/版本/OS/端口/上限的默认值）+ 包元信息
├── ssh.yaml  http.yaml  ftp.yaml  mysql.yaml  redis.yaml  tls.yaml
├── mail.yaml      # SMTP / POP3 / IMAP —— 超出必答范围，低成本增加深度
└── generic.yaml   # 兜底与关键词弱规则
```

### 一条真实规则（`rules/ssh.yaml` 里的 `ssh.openssh`，`#` 注释为本文标注）

```yaml
version: 1
pack: ssh
protocol: SSH                          # 本文件规则的默认协议
ports: [22, 2222, 2022, 8022, 10022]   # 协议级端口先验，规则未单独声明 ports 时继承
rules:
  - id: ssh.openssh
    description: "OpenSSH 标识串（RFC 4253 §4.2）"
    specificity: 100                   # 消歧用：越具体越高
    match:                             # ALL 必须命中
      - regex: '^SSH-(?P<sshver>[0-9]\.[0-9]{2})-(?P<product>OpenSSH)[-_](?P<version>[0-9][0-9A-Za-z.\-]*)'
    product: OpenSSH                   # 规范化产品名（不依赖 banner 原样大小写）
    os_hint:                           # 命中即取 value，可多条
      - {regex: '(?i)\bubuntu\b', value: Ubuntu}
      - {regex: '(?i)\bdebian\b', value: Debian}
      - {regex: '(?i)\bfreebsd\b', value: FreeBSD}
      - {regex: '(?i)\bcentos\b', value: CentOS}
      - {regex: '(?i)\brhel\b', value: Red Hat}
      - {regex: '(?i)\balpine\b', value: Alpine}
    score: {ceiling: 0.95, ceiling_no_version: 0.80}
```

`ceiling` 是怎么起作用的，用第 1 行样例走一遍：

- `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` 命中 `^SSH-…`（`protocol` +0.60）、`(?P<product>OpenSSH)`（+0.15）、`(?P<version>8.9p1)`（+0.10）；
- `os_hint` 里 `(?i)\bubuntu\b` 命中 → `Ubuntu`（+0.05）；
- 端口 22 落在该 pack 声明的 `ports` 内 → `port_agree` +0.05；
- 合计 0.95，恰好等于该规则的 `ceiling: 0.95`，于是输出 **0.95**。
- 若同一条规则换成没有版本串的 banner（例如 `SSH-2.0-OpenSSH` 截断），则 `ceiling_no_version`（本规则为 0.80）接管上限——**"认不全就不能给高分"这条约束写在数据里，而不是散落在代码里**。

### 加载与合并语义

1. **基线**：`go:embed rules/*.yaml`，规则随二进制走，`scratch` 空镜像自带完整规则包，镜像自包含、可复现。
2. **覆盖**：`--rules-dir /etc/bannerd/rules`（可用 `-v ./rules:/etc/bannerd/rules:ro` 挂载）。**同名文件整文件替换**内置同名 pack，目录里新增的 pack 直接追加。**不做"逐规则合并"** —— 整文件替换语义简单、可预测、易解释，避免"半覆盖"造成隐性行为差异。
3. **校验**：加载期用 `regexp.Compile` 编译每条正则，校验 `id` 唯一、`protocol` 非空、`score` 各项 ∈ [0,1] 且 `ceiling_no_version ≤ ceiling`；任一失败 → **启动即失败并打印出错的 `rule_id` 与原因**（fail fast），绝不静默跳过坏规则 —— 否则"规则写错了"会表现成"识别率莫名下降"，极难排查。
4. **加载时机**：规则集在**进程启动时一次性加载**，加载失败即拒绝启动（见上一条）。**没有运行期热加载** —— 改完 YAML 需要重启进程才会生效（`docker compose up -d --force-recreate server`，或本地重新 `go run`）。
5. **可观测**：`/health` 返回规则集 `source` / `schema_version` / `packs` / `count` / `sha256`，任何时刻都能确认"生效的是哪一版规则"。

### 可选：挂载外部规则目录（改完需重启）

默认 compose **不挂载** `rules/`（规则已 embed，保持镜像自包含）。想演示"改规则不用重编译"，直接用仓库里现成的示例目录 `examples/rules-override/` —— 它只新增一个 pack，把样例里唯一那条 `unknown`（`1.2.3.23:12345` 的 `QUIT`）认出来：

```bash
docker network create bannerd-demo-net
docker run --rm -d --name bannerd-demo --network bannerd-demo-net \
  -v "$PWD/examples/rules-override:/rules:ro" \
  bannerd-server:dev --rules-dir /rules
docker run --rm --network bannerd-demo-net -v "$PWD/testdata:/data:ro" \
  bannerd-client:dev --input /data/sample_input.json \
  --server http://bannerd-demo:8080 --format csv
```

`scripts/verify.ps1` / `scripts/verify.sh` 的第 6 步会自动跑一遍，并断言四件事（缺一不可）：

- 外部规则目录下的 server 自检仍然 **6/6** —— 新增 pack 没有破坏内置能力；
- `source` 变为 `/rules`、`packs` 由 9 变 **10** —— 是**新增**一个 pack，不是顶掉内置；
- 规则 `sha256` **随之改变** —— 换了规则，可复现凭据就必须变；
- 除被新规则认出来的那一条外，其余 19 行**一字未改** —— 只增不改，新增规则不该扰动任何已有结论。

想在 compose 里做同样的事，加一个 override 片段即可：

```yaml
# 需自行创建；用法: docker compose -f docker-compose.yaml -f docker-compose.rules.yaml up -d
services:
  server:
    command: ["--addr", "0.0.0.0:8080", "--rules-dir", "/etc/bannerd/rules"]
    volumes:
      - ./rules:/etc/bannerd/rules:ro
```

改完 YAML 后重启 server，`/health` 里的 `rules.sha256` / `rules.count` / `rules.packs` 就会随之变化；把一条正则改坏，进程会**在启动期直接失败并打印出错的 `rule_id`**（不会带病启动，也不会静默跳过坏规则）。

### DSL 的语法边界

正则引擎是 Go 的 **RE2**：天然无回溯、不存在 ReDoS，线性时间可预测；代价是 **不支持环视（lookahead / lookbehind）与反向引用**。写规则时如果用了这些构造，会在加载期被 `regexp.Compile` 拦下并报出 `rule_id`，不会等到线上才发现。

---

## 生产级部署说明

### 1. 网络收敛：只有一条路径

**用了什么**：compose 里只有一个用户自定义网络 `backend`（`driver: bridge`，`internal: true`）；server **刻意不写 `ports:`**；client 通过服务名 DNS 访问 `http://server:8080`；本地人工验证走独立的 `docker-compose.expose.yaml` 叠加，且只绑 `127.0.0.1:8080`。

**为什么**：把"容器间访问"收敛成唯一一条线，依赖关系和攻击面同时变清楚。`internal: true` 断掉容器的出网能力，也就断掉被攻破后回连与外传的通道；不发布宿主端口意味着默认形态下外部根本没有入口——需要调试时用 override **显式**打开，而不是让默认形态一直开着。`docker compose config` 里 server 没有 `ports:`、`docker network inspect` 显示 internal，两件事都可直接验。

### 2. 健康检测：检查的是识别能力，不是进程存活

**用了什么**：`/health` 每次真的跑 6 条探针 banner 过引擎并断言结果，失败返回 503 与 `{name, want, got}`；compose 的 healthcheck 执行 `bannerd healthcheck --url http://127.0.0.1:8080/health`；client 用 `depends_on: {server: {condition: service_healthy}}`。

**为什么**：三层都刻意选"更严格"的那个。探针断言的是**引擎还能不能识别**，所以"规则被改坏"这件事会被 healthcheck 直接抓到，而不是等业务请求出错。运行镜像是 `scratch`，里面没有 `curl`/`wget`，所以健康检测只能由程序自己发起——这反而正好，因为 `bannerd healthcheck` 打的是**应用语义端点**而不是 TCP 探活。`service_healthy` 让 client 等的是"健康"而不是"已启动"，避免抢跑拿到 `connection refused`，`docker compose up -d --wait` 也因此真的在等"能识别"。

### 3. 构建打包：Go 1.22 + vendor + `scratch`

**用了什么**：多阶段构建 `src → test → build → server / client`。`src` 层先 COPY 依赖清单与 `vendor/`、再 COPY 源码（改代码不失效依赖层）；`test` 层在构建期跑 `go vet ./... && go test ./...`；`build` 层 `CGO_ENABLED=0` + `-trimpath -buildvcs=false` + `-ldflags "-s -w -X …"` 注入版本号与 git sha；运行时 `scratch`，非 root `65532:65532`。构建镜像 `golang:1.22-alpine3.20`，唯一依赖 `gopkg.in/yaml.v3` 已 vendor 进仓库，`GOTOOLCHAIN=local`、`GOFLAGS=-mod=vendor`。

**为什么这样打包**：`CGO_ENABLED=0` + `netgo,osusergo` 之后二进制完全静态，不依赖 glibc，`scratch` 直接可跑；`scratch` 里没有 shell、没有包管理器、没有 libc，即使应用被攻破也没有可用工具链打点。实测镜像大小：`bannerd-server:dev` **9 MB**、`bannerd-client:dev` **7.7 MB**（`scratch` + 静态二进制 + embed 规则）。**离线是硬要求**：本机 Docker Hub 直连不可达、`proxy.golang.org` 超时，所以整条构建链不能有任何"拉取"动作——vendor 化消掉 Go 侧下载，构建镜像用本地已有的 tag，运行时用 `scratch`（保留名，无需拉取），结论是 `docker compose build` **完全不需要网络**。代价是 `scratch` 没有 tzdata 也没有 CA 根证书：日志统一用 UTC / RFC3339；本服务端不发起任何出网 TLS 连接（client→server 走 compose 内网明文 HTTP），因此不需要 CA；将来若要出网 HTTPS，补一行 `COPY --from=build /etc/ssl/certs/ca-certificates.crt` 即可。

### 4. 权限收紧

| 项 | 配置 | 效果 |
|---|---|---|
| 用户 | `USER 65532:65532` + compose `user:` | 非 root；数字 UID 不依赖 `/etc/passwd` |
| 根文件系统 | `read_only: true` | 容器不能改写自身文件系统 |
| 可写区 | `tmpfs /tmp:rw,noexec,nosuid,size=16m` | 唯一可写点，且不可执行 |
| Capabilities | `cap_drop: [ALL]` | 丢弃全部 capability（监听 8080 不需要 `CAP_NET_BIND_SERVICE`） |
| 提权 | `security_opt: ["no-new-privileges:true"]` | 禁止 setuid 类提权 |
| 进程数 | `pids_limit: 128`（server）/ `64`（client） | 限制 fork 炸弹 |
| 资源 | CPU / 内存 limits | 限制资源耗尽 |
| 日志 | `json-file` + `max-size: 10m` / `max-file: 3` | 防止日志写爆宿主磁盘 |
| 网络 | `internal: true`、无端口发布 | 无出网、无外部入口 |
| 停机 | `stop_grace_period: 10s` + 进程处理 SIGTERM | 优雅排空在途请求，而不是硬杀 |

`restart: unless-stopped` 只给 server（长驻服务）；client 是一次性批处理程序，`restart: "no"`。

---

## 本地开发与测试

```bash
go build ./...          # 构建
go vet ./...            # 静态检查
go test ./...           # 全部单测（含转义双模解码、评分公式、消歧平局、规则校验拒绝非法正则）
go test ./... -count=1  # 不吃测试缓存
```

`Makefile` 入口：

| 目标 | 作用 |
|---|---|
| `make test` | `go test ./...` |
| `make lint` | `gofmt -l ./cmd ./internal` 格式校验 + `go vet ./...`（刻意不引入任何需要联网下载的第三方 linter） |
| `make build` | 本机构建 `bannerd` / `bannerctl` |
| `make image` | `docker compose --profile run build`（client 在 `run` profile 里，不显式带 `--profile run` 会被跳过） |
| `make up` | `docker compose up -d --wait`（server 起来并 healthy） |
| `make up-expose` | 叠加 `docker-compose.expose.yaml` 启动，把 `127.0.0.1:8080` 放出来 |
| `make verify` | 一键端到端验收（等价于 `scripts/verify.*`） |
| `make down` | `docker compose down -v` |

---

## 如何验证

一键验收（推荐）：

```powershell
.\scripts\verify.ps1      # Windows
```

```bash
./scripts/verify.sh       # Linux / macOS
make verify               # 等价入口
```

验收脚本做的事：`docker compose --profile run build` → `up -d --wait`（等 healthcheck 真正通过，不是 sleep）→ 在 server 容器内跑 `bannerd healthcheck`（`scratch` 里没有 curl，健康只能自证）→ 经 client 容器发起批量识别 → 断言 20 条结果的条数 / 顺序 / 逐字段（7 行验收样例 + 8 个额外能力点）→ 再起一台**只换了规则目录**的 server，验证"换规则不换代码" → `down`。

注意：**验收脚本不直接跑 `go test`。** 单元测试在镜像构建阶段（`Dockerfile` 的 `test` 阶段）和 `make test` 里跑；验收脚本只回答一个问题——把镜像真的跑起来之后，任务要求的那几条还能不能对上。

```bash
# 1) 构建（无需联网；client 在 run profile 里，要显式带 --profile run）
docker compose -f docker-compose.yaml --profile run build

# 2) 启动并等健康检查真正通过
docker compose up -d --wait
docker compose ps                       # server 的 health 列应为 healthy

# 3) 端到端跑一遍样例
docker compose run --rm client                      # 表格
docker compose run --rm client --format csv | head  # 一行一条，便于对比

# 4) 看健康自检内容（规则集 source / schema_version / packs / count / sha256 与探针结果）
docker compose -f docker-compose.yaml -f docker-compose.expose.yaml up -d
curl -sS http://127.0.0.1:8080/health

# 5) 裸数组与 {"items":[...]} 对象入参都通；服务端刻意不校验 Content-Type
curl -sS -D- -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data-binary @testdata/sample_input.json
curl -sS -X POST http://127.0.0.1:8080/fingerprint \
  --data-binary '{"items":[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]}'
# 逐条诊断信息用 ?debug=1；命中数 / 耗时 / 规则哈希看响应头（上面 -D- 打印出来的那些）

# 6) 收摊
docker compose down -v
```

---

## 设计取舍与已知边界

- **TLS 不臆造版本。** banner 是裸 TLS 记录（`\x16\x03\x01…`）时，只报 `protocol: "TLS"`，`version` 留空，置信度 0.60。原因：记录头里的 `03 01` 是 **record version**，在 ClientHello 上几乎恒为兼容用的 legacy 值，**不代表协商出的版本**。宁可给低分，也不编一个 `1.0` 出来；原始字节留在 `?debug=1` 的附加字段里供人工研判。
- **`unknown` 不是错误。** 设计立场：认不出来是正常业务结果，不是异常。所以空 banner、纯 NUL、乱码、超长、`QUIT\r\n` 都返回 `protocol: "unknown"` + `confidence: 0`，整体 200，绝不因为认不出就 500 或丢条目。
- **响应永远是裸数组，元数据全走响应头。** 严格对齐任务示例；命中数 / 耗时 / 规则 sha256 都在 `X-Bannerd-*` 响应头里，既不改调用方的解析代码，也不丢信息量。
- **外部规则整文件替换，不逐规则合并。** 同名 pack 整文件覆盖内置，语义可预测、易于解释；避免"半覆盖"造成的隐性行为差异。
- **RE2 语法子集。** 不支持环视与反向引用，换来线性时间与无 ReDoS。规则写错在加载期就带 `rule_id` 失败。
- **规则默认 embed 而非挂载。** 保持镜像自包含、可复现；挂载只作为"改规则不重编译"的演示手段（见上文 override 片段）。
- **`scratch` 的代价。** 没有 shell / curl / tzdata / CA。日志统一 UTC；健康检测必须由程序自证；当前不出网所以不需要 CA。
- **端口只是弱先验。** 非标端口不影响识别（`Server: nginx/1.25.3` @8443 照样命中）；反过来，端口吻合也不会把分数推到上限之上。
- **没有认证、没有传输层加密、没有持久化。** 这是一个内网单跳的批处理识别服务，定位如此，`api/openapi.yaml` 里也没有这些内容。若要暴露到不可信网络，需要自己在前面加反向代理与访问控制——本项目不含这部分。
- **确定性优先于"聪明"。** 识别过程无随机、无时间依赖、无 map 迭代序：同一输入必然产出同一输出，才能用黄金文件做断言。

---

## 目录结构

```text
├── plan.md                     # 设计文档
├── README.md                   # 本文
├── api/openapi.yaml            # 接口契约（OpenAPI 3.0.3）
├── go.mod  go.sum  vendor/     # go 1.22；唯一依赖 yaml.v3 已 vendor
├── Makefile                    # image / build / test / vet / lint / up / verify / down 等 16 个目标
├── Dockerfile                  # src → test → build → server / client (scratch)
├── docker-compose.yaml         # 默认：锁死形态（无端口发布、internal 网络）
├── docker-compose.expose.yaml  # 可选：仅本地人工验证
├── cmd/      server/  client/
├── internal/ api/  engine/  rules/  banner/  config/  version/
├── rules/    _pack.yaml ssh.yaml http.yaml ftp.yaml mysql.yaml
│             redis.yaml tls.yaml mail.yaml generic.yaml
├── testdata/ sample_input.json  sample_input_loose.json  expected_20.json
│             demo_input.json   # 抓着录的真实 banner（含 Jetty(11.0.24)、Postfix 等）
├── examples/ rules-override/   # 「换规则不换代码」的演示规则目录
└── scripts/  verify.ps1  verify.sh
```
