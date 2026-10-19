#Requires -Version 5.1
<#
.SYNOPSIS
    Banner 指纹识别系统 —— 端到端验收脚本（Docker Compose 路线）。

.DESCRIPTION
    这个脚本回答一个问题：**把镜像真的跑起来之后，任务要求的那几条还能不能对上？**
    单元测试只能证明引擎在宿主机上是对的；这里证明的是「构建 → 编排 → 健康门禁 →
    容器间调用 → 识别深度」这一整条交付链是通的。

    它按顺序做七件事，任一步失败立刻以非 0 退出：
      1. docker compose --profile run build
      2. docker compose up -d --wait（--wait 会等到 healthcheck 通过）
      3. 在 server 容器内跑 bannerd healthcheck（scratch 里没有 curl，只能自证）
      4. 通过 client 容器发起批量识别（client → backend 网络 → server:8080）
      5. 断言验收样例的 7 行逐字段命中，以及 20 条的条数/顺序/unknown 计数
      6. 换一个规则目录再起一台 server，证明识别能力来自规则文件而不是代码
      7. 默认清理容器

.PARAMETER KeepUp
    验收结束后不拆除容器，方便接着手工排查。

.PARAMETER SkipBuild
    跳过构建，直接用现有镜像（改规则文件后快速复验用）。

.PARAMETER TimeoutSeconds
    `up --wait` 的健康等待上限，默认 120 秒。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
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

# PowerShell 5.1 有个老毛病：脚本级 $ErrorActionPreference = 'Stop' 时，原生命令写往
# stderr 的**任何一行**都会被当成终止性错误（NativeCommandError）抛出来。而 docker 与
# docker compose 恰恰把正常进度（"Container bannerd-server Healthy"）也写 stderr，
# 于是"检查容器健不健康"这句话本身会把脚本打断。所有原生命令都必须经由这里调用，
# 在局部把错误动作降级为 Continue，然后由我们自己看退出码判断成败。
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        # 只要 stdout。client 把 JSON 写 stdout、把摘要与诊断写 stderr，
        # 混在一起就得靠"截取第一个 [ 到最后一个 ]"这种脆弱办法。
        [switch]$StdoutOnly
    )

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    # 落盘再读：这样 stdout 与 stderr 是干净分离的两份文本，
    # 不会出现"ErrorRecord 与字符串混在同一个数组里被 Out-String 拼起来"的情况。
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        if ($StdoutOnly) {
            & $Exe @Arguments 1>$outFile 2>$null
        }
        else {
            & $Exe @Arguments 1>$outFile 2>$errFile
        }
        $code = $LASTEXITCODE
        $stdout = [System.IO.File]::ReadAllText($outFile)
        $stderr = if ($StdoutOnly) { '' } else { [System.IO.File]::ReadAllText($errFile) }
    }
    finally {
        $ErrorActionPreference = $previous
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        Stdout   = $stdout
        Stderr   = $stderr
        Output   = ($stdout + $stderr)
        ExitCode = $code
    }
}

function Invoke-Compose {
    # 参数走显式数组，而不是 ValueFromRemainingArguments：compose 的选项里有 -d
    # 这种单字母开关，PowerShell 会先拿它去匹配本函数的参数名而直接报错。
    # 另外这里不把参数命名为 $Args —— 那是 PowerShell 的自动变量，不可赋值。
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)

    $r = Invoke-Native -Exe 'docker' -Arguments (@('compose') + $ComposeArgs)
    if ($r.ExitCode -ne 0) {
        Write-Host $r.Output
        throw "docker compose $($ComposeArgs -join ' ') 失败（退出码 $($r.ExitCode)）"
    }
    return $r.Output
}

try {
    if (-not $SkipBuild) {
        Write-Step '1/7 构建镜像（多阶段：src → test → build → scratch）'
        # client 服务带 profiles: ["run"]，不属于默认 profile。不显式 --profile run
        # 的话 `compose build` 只会构建 server 镜像，client 镜像要等到 `compose run`
        # 时才临时补建 —— 那会让"构建阶段"变得不可预测，所以这里显式把它带进来。
        Invoke-Compose -ComposeArgs @('--profile', 'run', 'build') | Out-Null
    }
    else {
        Write-Step '1/7 跳过构建（-SkipBuild）'
    }

    Write-Step "2/7 启动编排并等待健康（上限 ${TimeoutSeconds}s）"
    Invoke-Compose -ComposeArgs @('up', '-d', '--wait', '--wait-timeout', "$TimeoutSeconds") | Out-Null
    $ps = Invoke-Compose -ComposeArgs @('ps')
    $ps.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Host "    $_" }

    Write-Step '3/7 server 自证健康（scratch 镜像里没有 curl，只有 bannerd 自己能探）'
    $hc = Invoke-Native -Exe 'docker' -Arguments @(
        'compose', 'exec', '-T', 'server',
        '/usr/local/bin/bannerd', 'healthcheck', '--url', 'http://127.0.0.1:8080/health'
    )
    $hc.Output.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Host "    $_" }
    Assert-That 'healthcheck 退出码为 0' ($hc.ExitCode -eq 0) "退出码 $($hc.ExitCode)"

    Write-Step '4/7 经 client 容器发起批量识别（唯一跨容器路径）'
    $run = Invoke-Native -StdoutOnly -Exe 'docker' -Arguments @(
        'compose', 'run', '--rm', '-T', 'client',
        '--input', '/data/sample_input.json', '--format', 'json'
    )
    # client 的契约是「JSON 走 stdout，摘要与诊断走 stderr」，所以这里拿到的就是纯 JSON。
    $text = $run.Stdout.Trim()
    if (-not $text.StartsWith('[')) {
        Write-Host $run.Stdout
        Write-Host $run.Stderr
        throw "client 的 stdout 不是 JSON 数组（开头是 $($text.Substring(0, [Math]::Min(40, $text.Length)))）"
    }
    # 先赋值、再 @()：Windows PowerShell 5.1 的 ConvertFrom-Json 把整个 JSON 数组
    # 当成**一个**对象发出（不展开），所以 `@(ConvertFrom-Json …)` 得到的是
    # 「装着 20 条的那个数组」——Count 会是 1，$got.confidence 也会变成数组。
    $parsed = ConvertFrom-Json -InputObject $text
    if ($null -eq $parsed) { throw 'client 输出的 JSON 解析为 null' }
    $results = @($parsed)

    Write-Step '5/7 断言识别深度'
    Assert-That '结果条数与输入一致（20 条，顺序不变）' ($results.Count -eq 20) "实际 $($results.Count)"

    $identified = @($results | Where-Object { $_.protocol -ne 'unknown' })
    $unknown = @($results | Where-Object { $_.protocol -eq 'unknown' })
    Assert-That '19 条识别成功' ($identified.Count -eq 19) "实际 $($identified.Count)"
    Assert-That '1 条按 unknown 返回（不算错误，服务不崩）' ($unknown.Count -eq 1) "实际 $($unknown.Count)"

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
        $label = "{0}:{1} → {2}/{3}/{4} @{5}" -f $want.ip, $want.port, $want.protocol, $want.product, $want.version, $want.confidence
        if ($null -eq $got) {
            Assert-That $label $false '结果里没有这一条'
            continue
        }
        $same = ($got.protocol -eq $want.protocol) -and
                ($got.product -eq $want.product) -and
                ($got.version -eq $want.version) -and
                ($got.os_hint -eq $want.os_hint) -and
                ([Math]::Abs([double]$got.confidence - [double]$want.confidence) -lt 1e-9)
        $detail = if ($same) { '' } else {
            "实际 {0}/{1}/{2}/{3}/{4}" -f $got.protocol, $got.product, $got.version, $got.os_hint, $got.confidence
        }
        Assert-That $label $same $detail
    }

    # 规则的 sha256 是"可复现"的凭据：换个规则文件，这个值必然变。
    $rules = Invoke-Native -Exe 'docker' -Arguments @(
        'compose', 'exec', '-T', 'server', '/usr/local/bin/bannerd', 'rules'
    )
    $shaLine = @($rules.Output -split "`r?`n" | Where-Object { $_ -match 'sha256=' })[0]
    if (-not $shaLine) { $shaLine = '（未取到规则指纹）' }
    Write-Host "    $($shaLine.Trim())"
    Assert-That '内置规则集指纹可用（64 位十六进制）' ($shaLine -match 'sha256=[0-9a-f]{64}') $shaLine

    # ------------------------------------------------------------ 6/7 解耦验证
    #
    # 「识别规则与程序代码解耦」这句主张，如果不演示，就只是一句主张。
    # 这里用**同一份不可变镜像**再起一台 server，唯一区别是规则目录换成了
    # examples/rules-override/，于是样例里唯一那条 unknown 被认了出来。
    # 全程不编译、不重建镜像、不碰一行 Go 代码。
    Write-Step '6/7 规则与代码解耦验证：同一份镜像，换规则目录，不重新编译'
    $demoNet = 'bannerd-verify-demo'
    $demoCtr = 'bannerd-verify-demo'
    Invoke-Native -Exe 'docker' -Arguments @('rm', '-f', $demoCtr) | Out-Null
    Invoke-Native -Exe 'docker' -Arguments @('network', 'rm', $demoNet) | Out-Null
    try {
        $null = Invoke-Native -Exe 'docker' -Arguments @('network', 'create', $demoNet)
        $started = Invoke-Native -Exe 'docker' -Arguments @(
            'run', '--rm', '-d', '--name', $demoCtr, '--network', $demoNet,
            '-v', (Join-Path $RepoRoot 'examples/rules-override' | ForEach-Object { "${_}:/rules:ro" }),
            'bannerd-server:dev', '--rules-dir', '/rules'
        )
        if ($started.ExitCode -ne 0) { throw "起演示容器失败：$($started.Output)" }

        # 等就绪用镜像自带的 healthcheck 子命令轮询，不靠 sleep 猜。
        $ready = $false
        $probeOut = ''
        for ($i = 0; $i -lt 40; $i++) {
            $probe = Invoke-Native -Exe 'docker' -Arguments @(
                'exec', $demoCtr, '/usr/local/bin/bannerd', 'healthcheck', '--url', 'http://127.0.0.1:8080/health'
            )
            if ($probe.ExitCode -eq 0) { $ready = $true; $probeOut = $probe.Output; break }
            Start-Sleep -Milliseconds 250
        }
        Assert-That '挂了外部规则目录的 server 自检仍然 6/6' $ready '2 秒内没健康起来'
        Assert-That '规则来源指向挂载目录' ($probeOut -match '"source":"/rules"') $probeOut
        # 新增 pack 而不是替换：内置 9 个 pack 一个不少，只是多了一个。
        Assert-That 'pack 数 9 → 10（是新增，不是顶掉内置）' ($probeOut -match '"packs":10') $probeOut

        $demoSha = if ($probeOut -match 'sha256":"([0-9a-f]{64})') { $Matches[1] } else { '' }
        $builtinSha = if ($shaLine -match 'sha256=([0-9a-f]{64})') { $Matches[1] } else { '' }
        Assert-That '规则指纹随之改变（换了规则，凭据就必须变）' `
            (($demoSha.Length -eq 64) -and ($demoSha -ne $builtinSha)) "demo=$demoSha builtin=$builtinSha"

        $demoCsv = Invoke-Native -StdoutOnly -Exe 'docker' -Arguments @(
            'run', '--rm', '--network', $demoNet,
            '-v', (Join-Path $RepoRoot 'testdata' | ForEach-Object { "${_}:/data:ro" }),
            'bannerd-client:dev', '--input', '/data/sample_input.json',
            '--server', "http://${demoCtr}:8080", '--format', 'csv'
        )
        $rows = @($demoCsv.Stdout.Trim() -split "`r?`n" | Where-Object { $_ })
        Assert-That '样例 #20 由 unknown 变为 Demo/QuitEcho @0.70' `
            ($rows -contains '1.2.3.23,12345,Demo,QuitEcho,,,0.70') "实际：$($rows[-1])"

        # 新增规则只应"多认出来一条"，不该扰动任何已有结论。
        $drift = @()
        foreach ($r in $results) {
            if ($r.ip -eq '1.2.3.23') { continue }
            $wantRow = '{0},{1},{2},{3},{4},{5},{6:F2}' -f $r.ip, $r.port, $r.protocol, $r.product, $r.version, $r.os_hint, $r.confidence
            if (-not ($rows -contains $wantRow)) { $drift += $wantRow }
        }
        Assert-That '其余 19 条结论一字未改（只增不改）' ($drift.Count -eq 0) ("漂移 $($drift.Count) 行")
    }
    finally {
        Invoke-Native -Exe 'docker' -Arguments @('rm', '-f', $demoCtr) | Out-Null
        Invoke-Native -Exe 'docker' -Arguments @('network', 'rm', $demoNet) | Out-Null
    }

    Write-Step '7/7 收尾'
    if ($KeepUp) {
        Write-Host '    -KeepUp 已指定，容器保留。停止：docker compose down'
    }
    else {
        Invoke-Compose -ComposeArgs @('down', '--remove-orphans') | Out-Null
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
Write-Host ("验收通过：{0}/{0} 项全部命中。" -f $script:Checks) -ForegroundColor Green
exit 0
