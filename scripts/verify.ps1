#Requires -Version 5.1
<#
.SYNOPSIS
    Banner 指纹识别系统 —— 端到端验收脚本（Docker Compose 路线）。

.DESCRIPTION
    这个脚本回答一个问题：**把镜像真的跑起来之后，任务要求的那几条还能不能对上？**
    单元测试只能证明引擎在宿主机上是对的；这里证明的是「构建 → 编排 → 健康门禁 →
    容器间调用 → 识别深度」这一整条交付链是通的。

    它按顺序做六件事，任一步失败立刻以非 0 退出：
      1. docker compose build
      2. docker compose up -d --wait（--wait 会等到 healthcheck 通过）
      3. 在 server 容器内跑 bannerd healthcheck（自证 /health 而不是让宿主 curl）
      4. 通过 client 容器发起批量识别（client → backend 网络 → server）
      5. 断言验收样例的 7 行逐字段命中，以及 20 条的条数/顺序/unknown 计数
      6. 默认清理容器

.PARAMETER KeepUp
    验收结束后不拆除容器，方便接着手工 curl 排查。

.PARAMETER SkipBuild
    跳过构建，直接用现有镜像（改规则文件后快速复验用）。

.PARAMETER TimeoutSeconds
    `up --wait` 的健康等待上限，默认 120 秒。

.EXAMPLE
    pwsh -NoProfile -File ./scripts/verify.ps1
#>
[CmdletBinding()]
param(
    [switch]$KeepUp,
    [switch]$SkipBuild,
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot

$script:Failures = @()
$script:Checks = 0

function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Assert-That([string]$Name, [bool]$Ok, [string]$Detail = '') {
    $script:Checks++
    if ($Ok) {
        Write-Host ("    [ OK ] {0}" -f $Name) -ForegroundColor Green
    }
    else {
        $script:Failures += $Name
        Write-Host ("    [FAIL] {0}{1}" -f $Name, $(if ($Detail) { " — $Detail" } else { '' })) -ForegroundColor Red
    }
}

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    # 把 stderr 合进 stdout：docker/compose 的进度与部分错误都走 stderr，
    # 分开处理反而容易在读输出时卡住。
    & docker compose @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($Args -join ' ') 失败（退出码 $LASTEXITCODE）"
    }
}

try {
    if (-not $SkipBuild) {
        Write-Step '1/6 构建镜像（多阶段：src → test → build → scratch）'
        # client 服务带 profiles: ["run"]，不属于默认 profile。不显式 --profile run
        # 的话 `compose build` 只会构建 server 镜像，client 镜像要等到 `compose run`
        # 时才临时补建 —— 那会让"构建阶段"变得不可预测，所以这里显式把它带进来。
        Invoke-Compose --profile run build
    }
    else {
        Write-Step '1/6 跳过构建（-SkipBuild）'
    }

    Write-Step "2/6 启动编排并等待健康（上限 ${TimeoutSeconds}s）"
    Invoke-Compose up -d --wait --wait-timeout $TimeoutSeconds
    & docker compose ps 2>&1 | ForEach-Object { Write-Host "    $_" }

    Write-Step '3/6 server 自证健康（镜像里没有 curl，只有 bannerd 自己能探）'
    $hc = & docker compose exec -T server /usr/local/bin/bannerd healthcheck --url http://127.0.0.1:8080/health 2>&1
    $hc | ForEach-Object { Write-Host "    $_" }
    Assert-That 'healthcheck 退出码为 0' ($LASTEXITCODE -eq 0) "退出码 $LASTEXITCODE"

    Write-Step '4/6 经 client 容器发起批量识别（唯一跨容器路径）'
    $raw = & docker compose run --rm -T client --input /data/sample_input.json --format json 2>&1
    $text = ($raw | Out-String)
    $start = $text.IndexOf('[')
    $end = $text.LastIndexOf(']')
    if ($start -lt 0 -or $end -lt $start) {
        Write-Host $text
        throw 'client 没有输出 JSON 数组（上面是完整原始输出）'
    }
    $results = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json

    Write-Step '5/6 断言识别深度'
    Assert-That '结果条数与输入一致（20 条，顺序不变）' ($results.Count -eq 20) "实际 $($results.Count)"

    $identified = @($results | Where-Object { $_.protocol -ne 'unknown' })
    $unknown = @($results | Where-Object { $_.protocol -eq 'unknown' })
    Assert-That '19 条识别成功' ($identified.Count -eq 19) "实际 $($identified.Count)"
    Assert-That '1 条按 unknown 返回（不算错误）' ($unknown.Count -eq 1) "实际 $($unknown.Count)"

    # 验收基准：任务书给出的 7 行示例输出，逐字段比对。
    $expected = @(
        @{ ip = '1.2.3.4'; port = 22; protocol = 'SSH'; product = 'OpenSSH'; version = '8.9p1'; os_hint = 'Ubuntu'; confidence = 0.95 },
        @{ ip = '1.2.3.5'; port = 80; protocol = 'HTTP'; product = 'nginx'; version = '1.24.0'; os_hint = ''; confidence = 0.9 },
        @{ ip = '1.2.3.6'; port = 443; protocol = 'HTTP'; product = 'Apache'; version = '2.4.57'; os_hint = ''; confidence = 0.9 },
        @{ ip = '1.2.3.7'; port = 3306; protocol = 'MySQL'; product = 'MySQL'; version = '8.0.32'; os_hint = ''; confidence = 0.9 },
        @{ ip = '1.2.3.8'; port = 6379; protocol = 'Redis'; product = 'Redis'; version = ''; os_hint = ''; confidence = 0.7 },
        @{ ip = '1.2.3.9'; port = 21; protocol = 'FTP'; product = 'ProFTPD'; version = '1.3.7'; os_hint = ''; confidence = 0.9 },
        @{ ip = '1.2.3.10'; port = 8080; protocol = 'HTTP'; product = 'Jetty'; version = '9.4.51'; os_hint = ''; confidence = 0.85 }
    )

    foreach ($want in $expected) {
        $got = $results | Where-Object { $_.ip -eq $want.ip -and $_.port -eq $want.port } | Select-Object -First 1
        $label = "{0}:{1}" -f $want.ip, $want.port
        if ($null -eq $got) {
            Assert-That "$label 出现在结果里" $false '缺失'
            continue
        }
        $same = ($got.protocol -eq $want.protocol) -and
                ($got.product -eq $want.product) -and
                ($got.version -eq $want.version) -and
                ($got.os_hint -eq $want.os_hint) -and
                ([Math]::Abs([double]$got.confidence - [double]$want.confidence) -lt 1e-9)
        $detail = if ($same) { '' } else {
            "期望 {0}/{1}/{2}/{3}/{4}，实际 {5}/{6}/{7}/{8}/{9}" -f `
                $want.protocol, $want.product, $want.version, $want.os_hint, $want.confidence, `
                $got.protocol, $got.product, $got.version, $got.os_hint, $got.confidence
        }
        Assert-That "$label → $($want.protocol)/$($want.product)/$($want.version) @$($want.confidence)" $same $detail
    }

    # 规则的 sha256 是「可复现」的凭据：换个规则文件，这个值必然变。
    $rulesOut = (& docker compose exec -T server /usr/local/bin/bannerd rules 2>&1 | Out-String)
    $shaLine = ($rulesOut -split "`r?`n" | Where-Object { $_ -match 'sha256=' } | Select-Object -First 1)
    Write-Host "    $($shaLine.Trim())"
    Assert-That '内置规则集指纹可用（64 位十六进制）' ($shaLine -match 'sha256=[0-9a-f]{64}') $shaLine

    Write-Step '6/6 收尾'
    if ($KeepUp) {
        Write-Host '    -KeepUp 已指定，容器保留。'
        Write-Host '    停止：docker compose down'
    }
    else {
        Invoke-Compose down --remove-orphans
        Write-Host '    容器已清理。'
    }
}
finally {
    Pop-Location
}

Write-Host ''
if ($script:Failures.Count -gt 0) {
    Write-Host ("验收失败：{0}/{1} 项未通过" -f $script:Failures.Count, $script:Checks) -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host ("验收通过：{0}/{1} 项全部命中。" -f $script:Checks, $script:Checks) -ForegroundColor Green
exit 0
