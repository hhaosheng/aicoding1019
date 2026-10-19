#!/usr/bin/env bash
#
# bannerd 端到端验收（Linux / macOS / WSL / Git Bash）。
#
# 与 scripts/verify.ps1 等价：把系统用 Docker Compose 整起来，再从 client 容器
# 发起一次真实识别，然后逐项断言。两者都只走编排暴露出来的那条路径
# （client → http://server:8080），不绕过入口去直接调二进制 —— 验收的应该是
# 交付出去的那个东西，不是本地开发时的替身。
#
#   ./scripts/verify.sh               全量：构建 → 启动 → 断言 → 清理
#   ./scripts/verify.sh --skip-build  复用已有镜像
#
set -euo pipefail

# Git Bash / MSYS 会把 `/data/sample_input.json` 这类参数当 Windows 路径改写，
# 于是容器里找不到文件。这两个变量关掉改写；在 Linux/macOS 上无副作用。
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

COMPOSE=(docker compose -f docker-compose.yaml)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 挂载路径要交给 docker，而 Git Bash 给的是 /d/code/... 这种 POSIX 形态。
# cygpath -m 转成 D:/code/... （混合分隔符），docker 认；Linux/macOS 上原样用。
if command -v cygpath >/dev/null 2>&1; then
	ROOT_MOUNT="$(cygpath -m "$ROOT")"
else
	ROOT_MOUNT="$ROOT"
fi

DEMO_NET='bannerd-verify-demo'
DEMO_CTR='bannerd-verify-demo'
SKIP_BUILD=0

for arg in "$@"; do
	case "$arg" in
		--skip-build) SKIP_BUILD=1 ;;
		-h | --help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*)
			echo "未知参数：$arg" >&2
			exit 2
			;;
	esac
done

pass=0
fail=0

step() { printf '\n==> %s\n' "$1"; }
ok() { printf '    [ OK ] %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '    [FAIL] %s\n' "$1"; fail=$((fail + 1)); }

# assert 判一条布尔表达式；失败不中断，最后统一汇报。
assert() {
	local desc="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		ok "$desc"
	else
		bad "$desc"
	fi
}

# expect_row 在 CSV 结果里找一整行，用于断言识别深度。
# 用整行精确匹配而不是子串：半截匹配会让"识别出了一个看着像但其实错的版本"蒙混过关。
expect_row() {
	local desc="$1" want="$2"
	if printf '%s\n' "$csv" | grep -qxF "$want"; then
		ok "$desc"
	else
		bad "$desc"
		printf '           期望整行：%s\n' "$want"
		printf '           实际含该 IP 的行：\n'
		printf '%s\n' "$csv" | grep -F "$(printf '%s' "$want" | cut -d, -f1)" | sed 's/^/             /' || true
	fi
}

cleanup() {
	printf '\n==> 7/7 收尾\n'
	docker rm -f "$DEMO_CTR" >/dev/null 2>&1 || true
	docker network rm "$DEMO_NET" >/dev/null 2>&1 || true
	"${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
	echo '    容器已清理。'
}
trap cleanup EXIT

# ---------------------------------------------------------------- 1 构建
if [ "$SKIP_BUILD" -eq 1 ]; then
	step '1/7 跳过构建（--skip-build）'
else
	step '1/7 构建镜像（多阶段 → scratch；client 在 run profile 里，build 会自动按需构建）'
	"${COMPOSE[@]}" build
fi

# ---------------------------------------------------------------- 2 启动
step '2/7 启动编排并等待健康（--wait 由编排自己判定，不看 sleep）'
"${COMPOSE[@]}" up -d --wait --wait-timeout 120
"${COMPOSE[@]}" ps

# ---------------------------------------------------------------- 3 自检
step '3/7 server 自证健康（scratch 镜像里没有 curl，只有 bannerd 自己能探）'
if health=$("${COMPOSE[@]}" exec -T server /usr/local/bin/bannerd healthcheck --url http://127.0.0.1:8080/health 2>&1); then
	printf '    %s\n' "$health"
	ok 'healthcheck 退出码为 0'
else
	printf '    %s\n' "$health"
	bad 'healthcheck 退出码非 0（上面是完整响应体）'
fi

# ---------------------------------------------------------------- 4 识别
step '4/7 经 client 容器发起批量识别（唯一跨容器路径）'
# client 的契约是「结果走 stdout，摘要与诊断走 stderr」，所以这里拿到的就是纯 CSV。
csv=$("${COMPOSE[@]}" run --rm -T client --input /data/sample_input.json --format csv 2>/dev/null)

# ---------------------------------------------------------------- 5 断言
step '5/7 断言识别深度'

rows=$(printf '%s\n' "$csv" | grep -vc '^ip,port,protocol,product,version,os_hint,confidence$' || true)
if [ "$rows" -eq 20 ]; then ok '结果条数与输入一致（20 条，顺序不变）'; else bad "结果条数应为 20，实际 $rows"; fi

unknown=$(printf '%s\n' "$csv" | grep -c ',unknown,' || true)
if [ "$unknown" -eq 1 ]; then ok '1 条按 unknown 返回（不算错误，服务不崩）'; else bad "unknown 应为 1 条，实际 $unknown"; fi

if [ "$((rows - unknown))" -eq 19 ]; then ok '19 条识别成功'; else bad "识别成功应为 19 条，实际 $((rows - unknown))"; fi

echo '    --- 任务给的 7 行验收样例，逐字段 ---'
expect_row '1.2.3.4:22   → SSH/OpenSSH/8.9p1 @0.95' '1.2.3.4,22,SSH,OpenSSH,8.9p1,Ubuntu,0.95'
expect_row '1.2.3.5:80   → HTTP/nginx/1.24.0 @0.90' '1.2.3.5,80,HTTP,nginx,1.24.0,,0.90'
expect_row '1.2.3.6:443  → HTTP/Apache/2.4.57 @0.90' '1.2.3.6,443,HTTP,Apache,2.4.57,,0.90'
expect_row '1.2.3.7:3306 → MySQL/MySQL/8.0.32 @0.90' '1.2.3.7,3306,MySQL,MySQL,8.0.32,,0.90'
expect_row '1.2.3.8:6379 → Redis/Redis/（无版本）@0.70' '1.2.3.8,6379,Redis,Redis,,,0.70'
expect_row '1.2.3.9:21   → FTP/ProFTPD/1.3.7 @0.90' '1.2.3.9,21,FTP,ProFTPD,1.3.7,,0.90'
expect_row '1.2.3.10:8080→ HTTP/Jetty/9.4.51 @0.85' '1.2.3.10,8080,HTTP,Jetty,9.4.51,,0.85'

echo '    --- 其余能力点（样例里覆盖到但任务未逐行给出的） ---'
expect_row '1.2.3.11:22   → OpenSSH 9.3 / Debian' '1.2.3.11,22,SSH,OpenSSH,9.3,Debian,0.95'
expect_row '1.2.3.12:80   → nginx 1.18.0（发行版后缀被识别）' '1.2.3.12,80,HTTP,nginx,1.18.0,Ubuntu,0.95'
expect_row '1.2.3.13:443  → Apache 2.4.41（发行版后缀被识别）' '1.2.3.13,443,HTTP,Apache,2.4.41,Ubuntu,0.95'
expect_row '1.2.3.14:3306 → MySQL 5.7.42（字面量 \x00 转义也能过）' '1.2.3.14,3306,MySQL,MySQL,5.7.42,,0.90'
expect_row '1.2.3.16:21   → vsftpd 3.0.5（另一种 220 措辞）' '1.2.3.16,21,FTP,vsftpd,3.0.5,,0.90'
expect_row '1.2.3.19:9999 → TLS（record 头 16 03 01，识别为二进制协议）' '1.2.3.19,9999,TLS,,,,0.60'
expect_row '1.2.3.20:8888 → Microsoft-IIS 10.0 / Windows' '1.2.3.20,8888,HTTP,Microsoft-IIS,10.0,Windows,0.95'
expect_row '1.2.3.22:21   → Pure-FTPd（认得出但抽不到版本，0.75）' '1.2.3.22,21,FTP,Pure-FTPd,,,0.75'

echo '    --- 规则可复现性 --- '
if ruleline=$("${COMPOSE[@]}" exec -T server /usr/local/bin/bannerd rules 2>/dev/null | head -n 1); then
	printf '    %s\n' "$ruleline"
	case "$ruleline" in
		*source=embedded*packs=*rules=*sha256=*) ok '内置规则集指纹可用' ;;
		*) bad '规则集指纹行格式不对' ;;
	esac
else
	bad '无法读取规则集指纹'
fi

# ------------------------------------------------- 6 解耦验证（换规则不换代码）
#
# 「识别规则与程序代码解耦」这句主张，如果不演示，就只是一句主张。
# 这里用**同一份不可变镜像**再起一台 server，唯一区别是规则目录换成了
# examples/rules-override/，于是样例里唯一那条 unknown 被认了出来。
# 全程不编译、不重建镜像、不碰一行 Go 代码。
step '6/7 规则与代码解耦验证：同一份镜像，换规则目录，不重新编译'

docker rm -f "$DEMO_CTR" >/dev/null 2>&1 || true
docker network rm "$DEMO_NET" >/dev/null 2>&1 || true

if docker network create "$DEMO_NET" >/dev/null 2>&1 &&
	docker run --rm -d --name "$DEMO_CTR" --network "$DEMO_NET" \
		-v "$ROOT_MOUNT/examples/rules-override:/rules:ro" \
		bannerd-server:dev --rules-dir /rules >/dev/null 2>&1; then

	# 等就绪用镜像自带的 healthcheck 子命令轮询，不靠 sleep 猜。
	ready=0
	probe=''
	for _ in $(seq 1 40); do
		if probe=$(docker exec "$DEMO_CTR" /usr/local/bin/bannerd healthcheck \
			--url http://127.0.0.1:8080/health 2>&1); then
			ready=1
			break
		fi
		sleep 0.25
	done

	if [ "$ready" -eq 1 ]; then
		ok '挂了外部规则目录的 server 自检仍然 6/6'
		printf '    %s\n' "$probe"
	else
		bad '挂了外部规则目录的 server 没能健康起来'
		printf '    %s\n' "$probe"
	fi

	case "$probe" in
		*'"source":"/rules"'*) ok '规则来源指向挂载目录' ;;
		*) bad '规则来源没有指向挂载目录' ;;
	esac
	# 新增 pack 而不是替换：内置 9 个 pack 一个不少，只是多了一个。
	case "$probe" in
		*'"packs":10'*) ok 'pack 数 9 → 10（是新增，不是顶掉内置）' ;;
		*) bad 'pack 数没有变成 10' ;;
	esac

	demo_sha=$(printf '%s' "$probe" | sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
	builtin_sha=$(printf '%s' "$ruleline" | sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p')
	if [ "${#demo_sha}" -eq 64 ] && [ "$demo_sha" != "$builtin_sha" ]; then
		ok '规则指纹随之改变（换了规则，凭据就必须变）'
	else
		bad "规则指纹没有变化：demo=$demo_sha builtin=$builtin_sha"
	fi

	demo_csv=$(docker run --rm --network "$DEMO_NET" \
		-v "$ROOT_MOUNT/testdata:/data:ro" \
		bannerd-client:dev --input /data/sample_input.json \
		--server "http://${DEMO_CTR}:8080" --format csv 2>/dev/null || true)

	if printf '%s\n' "$demo_csv" | grep -qxF '1.2.3.23,12345,Demo,QuitEcho,,,0.70'; then
		ok '样例 #20 由 unknown 变为 Demo/QuitEcho @0.70'
	else
		bad '样例 #20 没有被新规则认出来'
		printf '%s\n' "$demo_csv" | grep -F '1.2.3.23,' | sed 's/^/            /' || true
	fi

	# 新增规则只应"多认出来一条"，不该扰动任何已有结论 —— 逐行比对除了 #20 之外的全部行。
	base_rest=$(printf '%s\n' "$csv" | grep -v '^ip,port' | grep -v '^1\.2\.3\.23,' || true)
	demo_rest=$(printf '%s\n' "$demo_csv" | grep -v '^ip,port' | grep -v '^1\.2\.3\.23,' || true)
	if [ "$base_rest" = "$demo_rest" ]; then
		ok '其余 19 条结论一字未改（只增不改）'
	else
		bad '新增规则扰动了其它结论'
		diff <(printf '%s\n' "$base_rest") <(printf '%s\n' "$demo_rest") | sed 's/^/            /' || true
	fi
else
	bad '起演示容器失败（跳过本步其余断言）'
fi

# ---------------------------------------------------------------- 7 收尾
if [ "$fail" -eq 0 ]; then
	printf '\n验收通过：%d/%d 项全部命中。\n' "$pass" "$((pass + fail))"
	exit 0
fi
printf '\n验收失败：%d 项通过，%d 项未通过。\n' "$pass" "$fail"
exit 1
