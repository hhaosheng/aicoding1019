#!/usr/bin/env bash
# ============================================================================
# Banner 指纹识别系统 —— 端到端验收脚本（POSIX / bash 路线）
#
# 与 scripts/verify.ps1 做同样的事，给非 Windows 环境使用：
#   1. docker compose --profile run build
#   2. docker compose up -d --wait   （--wait 会等到 healthcheck 通过）
#   3. 在 server 容器内跑 bannerd healthcheck（镜像里没有 curl，只能自证）
#   4. 通过 client 容器发起批量识别（client → backend 网络 → server:8080）
#   5. 断言验收样例 7 行逐字段命中 + 20 条条数/顺序/unknown 计数
#   6. 默认清理容器
#
# 用法：
#   ./scripts/verify.sh              # 完整验收
#   KEEP_UP=1 ./scripts/verify.sh    # 验完保留容器
#   SKIP_BUILD=1 ./scripts/verify.sh # 跳过构建，快速复验
# ============================================================================
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

KEEP_UP="${KEEP_UP:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-120}"

CHECKS=0
FAILURES=()

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_CYAN=""
fi

step()  { printf '\n%s==> %s%s\n' "$C_CYAN" "$1" "$C_RESET"; }
note()  { printf '    %s\n' "$1"; }
fail()  { FAILURES+=("$1"); printf '    %s[FAIL] %s%s\n' "$C_RED" "$1" "${2:+ — $2}" "$C_RESET"; }
pass()  { printf '    %s[ OK ] %s%s\n' "$C_GREEN" "$1" "$C_RESET"; }

assert() { # assert <名称> <0|1> [细节]
    CHECKS=$((CHECKS + 1))
    if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1" "${3:-}"; fi
}

cleanup() {
    if [ "$KEEP_UP" != "1" ]; then
        step '6/6 收尾'
        docker compose down --remove-orphans >/dev/null 2>&1 || true
        note '容器已清理。'
    else
        step '6/6 收尾'
        note 'KEEP_UP=1，容器保留。停止：docker compose down'
    fi
}
trap cleanup EXIT

# 依赖：jq 缺失时退回 python3，两者都没有就让断言降级为「只看计数」。
json_get() { # json_get <字段> <json文本>
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$2" | jq -r "$1"
    else
        printf '%s' "$2" | python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1"
    fi
}

if [ "$SKIP_BUILD" != "1" ]; then
    step '1/6 构建镜像（多阶段：src → test → build → scratch）'
    # client 服务带 profiles: ["run"]，必须显式带上才会一起构建。
    docker compose --profile run build
else
    step '1/6 跳过构建（SKIP_BUILD=1）'
fi

step "2/6 启动编排并等待健康（上限 ${TIMEOUT_SECONDS}s）"
docker compose up -d --wait --wait-timeout "$TIMEOUT_SECONDS"
docker compose ps

step '3/6 server 自证健康'
set +e
docker compose exec -T server /usr/local/bin/bannerd healthcheck --url http://127.0.0.1:8080/health
HC=$?
set -e
assert 'healthcheck 退出码为 0' "$HC" "退出码 $HC"

step '4/6 经 client 容器发起批量识别（唯一跨容器路径）'
RAW="$(docker compose run --rm -T client --input /data/sample_input.json --format json 2>&1)"
# 摘要行可能混在输出里，所以只截取第一个 '[' 到最后一个 ']' 之间。
JSON="$(printf '%s' "$RAW" | sed -n '/\[/,/\]/p')"
if [ -z "$JSON" ]; then
    printf '%s\n' "$RAW"
    echo 'client 没有输出 JSON 数组（上面是完整原始输出）' >&2
    exit 1
fi

step '5/6 断言识别深度'
TOTAL="$(printf '%s' "$JSON" | grep -c '"ip"' || true)"
assert '结果条数与输入一致（20 条）' "$([ "$TOTAL" -eq 20 ] && echo 0 || echo 1)" "实际 $TOTAL"

UNKNOWN="$(printf '%s' "$JSON" | grep -c '"protocol": "unknown"' || true)"
assert '1 条按 unknown 返回（不算错误）' "$([ "$UNKNOWN" -eq 1 ] && echo 0 || echo 1)" "实际 $UNKNOWN"

# 验收基准：任务书给出的 7 行示例输出，逐字段比对。
check_row() { # check_row ip port protocol product version os_hint confidence
    local ip="$1" port="$2" protocol="$3" product="$4" version="$5" oshint="$6" conf="$7"
    local block
    block="$(printf '%s' "$JSON" | tr -d ' \n' | grep -o "{[^{}]*\"ip\":\"$ip\",\"port\":$port[^{}]*}")"
    local label="$ip:$port → $protocol/$product/$version @$conf"
    if [ -z "$block" ]; then fail "$label" '缺失'; CHECKS=$((CHECKS + 1)); return; fi
    local ok=1
    case "$block" in *"\"protocol\":\"$protocol\""*) ;; *) ok=0 ;; esac
    case "$block" in *"\"product\":\"$product\""*) ;; *) ok=0 ;; esac
    case "$block" in *"\"version\":\"$version\""*) ;; *) ok=0 ;; esac
    case "$block" in *"\"os_hint\":\"$oshint\""*) ;; *) ok=0 ;; esac
    case "$block" in *"\"confidence\":$conf"*) ;; *) ok=0 ;; esac
    assert "$label" "$([ "$ok" -eq 1 ] && echo 0 || echo 1)" "$block"
}

check_row 1.2.3.4  22   SSH   OpenSSH 8.9p1  Ubuntu  0.95
check_row 1.2.3.5  80   HTTP  nginx   1.24.0 ""      0.9
check_row 1.2.3.6  443  HTTP  Apache  2.4.57 ""      0.9
check_row 1.2.3.7  3306 MySQL MySQL   8.0.32 ""      0.9
check_row 1.2.3.8  6379 Redis Redis   ""     ""      0.7
check_row 1.2.3.9  21   FTP   ProFTPD 1.3.7  ""      0.9
check_row 1.2.3.10 8080 HTTP  Jetty   9.4.51 ""      0.85

RULES_OUT="$(docker compose exec -T server /usr/local/bin/bannerd rules 2>&1 || true)"
SHA_LINE="$(printf '%s' "$RULES_OUT" | grep 'sha256=' | head -n1 || true)"
note "${SHA_LINE:-（未取到规则指纹）}"
assert '内置规则集指纹可用（64 位十六进制）' \
    "$(printf '%s' "$SHA_LINE" | grep -Eq 'sha256=[0-9a-f]{64}' && echo 0 || echo 1)" "$SHA_LINE"

echo
if [ "${#FAILURES[@]}" -gt 0 ]; then
    printf '%s验收失败：%d/%d 项未通过%s\n' "$C_RED" "${#FAILURES[@]}" "$CHECKS" "$C_RESET"
    for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done
    # trap 里会清理容器；这里先关掉 trap 以免重复
    trap - EXIT
    [ "$KEEP_UP" = "1" ] || docker compose down --remove-orphans >/dev/null 2>&1 || true
    exit 1
fi
printf '%s验收通过：%d/%d 项全部命中。%s\n' "$C_GREEN" "$CHECKS" "$CHECKS" "$C_RESET"
