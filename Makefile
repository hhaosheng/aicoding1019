# ============================================================================
# Banner 指纹识别系统 —— Makefile
# 统一入口：宿主机本地构建 / 测试 / 验收，以及 docker compose 的启动停止。
#
# 全程不需要外网：GOTOOLCHAIN=local + -mod=vendor（vendor/ 已提交进仓库），
# 与 Dockerfile 里的 ENV 完全一致，保证"宿主机能编译"与"容器能编译"行为一致。
# ============================================================================

# 不带目标直接 `make` 时打印帮助
.DEFAULT_GOAL := help

# —— 可覆盖变量（make VERSION=0.1.0 build 即可注入版本）——
GO       ?= go
VERSION  ?= dev
GIT_SHA  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BIN_DIR  ?= bin

# 与 Dockerfile 保持一致的离线基线
export GOTOOLCHAIN := local
export GOFLAGS     := -mod=vendor
export CGO_ENABLED := 0

# 与 Dockerfile 的 build 阶段一致的编译参数（版本注入 / 静态 / 可复现）
BUILD_TAGS := netgo,osusergo
LDFLAGS    := -s -w -X main.version=$(VERSION) -X main.gitSHA=$(GIT_SHA)
GOBUILD    := $(GO) build -trimpath -buildvcs=false -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)'
GOSRC      := ./cmd ./internal

# 验收脚本按平台分发：Windows 用 PowerShell，其余用 bash。
#
# 这里刻意用 powershell.exe 而不是 pwsh：前者是 Windows 自带组件，任何 Windows 上
# 都存在；PowerShell 7（pwsh）是可选的，很多机器上并没有装（本项目的开发机就没有，
# 只有 5.1）。scripts/verify.ps1 用 `#Requires -Version 5.1` 声明了最低版本，
# 两个版本都能跑，所以选"一定存在"的那个，而不是"通常更好"的那个。
ifeq ($(OS),Windows_NT)
VERIFY_CMD := powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
else
VERIFY_CMD := ./scripts/verify.sh
endif

.PHONY: help build test vet lint fmt run-server client health up up-expose down logs verify clean

help: ## 显示本帮助（默认目标）
	@echo "Banner 指纹识别系统 —— 可用目标："
	@echo
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo

build: ## 宿主机编译两个二进制到 bin/（bannerd + bannerctl）
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/bannerd  ./cmd/server
	$(GOBUILD) -o $(BIN_DIR)/bannerctl ./cmd/client
	@echo "构建完成：$(BIN_DIR)/bannerd 与 $(BIN_DIR)/bannerctl"

test: ## 运行全部单元测试（含黄金文件比对）
	$(GO) test ./... -count=1

vet: ## 运行 go vet 静态检查
	$(GO) vet ./...

lint: ## 静态检查：gofmt 格式校验 + go vet（不引入任何需联网下载的第三方 linter）
	@bad="$$(gofmt -l $(GOSRC))"; \
	if [ -n "$$bad" ]; then echo "以下文件未通过 gofmt，请执行 make fmt："; echo "$$bad"; exit 1; fi
	$(GO) vet ./...

fmt: ## 用 gofmt 格式化 cmd/ 与 internal/
	gofmt -l -w $(GOSRC)

run-server: build ## 宿主机前台启动 server（默认规则目录 ./rules）
	$(BIN_DIR)/bannerd --addr :8080 --rules-dir ./rules

health: ## 用二进制自身探测运行中的 server（scratch 镜像里没有 curl，只能自证）
	$(BIN_DIR)/bannerd healthcheck --url http://127.0.0.1:8080/health

client: build ## 用 client 把样例输入发给本机 server 并打印表格
	$(BIN_DIR)/bannerctl --input testdata/sample_input.json --server http://127.0.0.1:8080

up: ## 默认（锁定）形态启动：只起 server，无端口发布、网络 internal（等 healthy）
	docker compose -f docker-compose.yaml up -d --wait

up-expose: ## 仅本地人工验证：叠加 expose override 后启动（端口只绑 127.0.0.1）
	docker compose -f docker-compose.yaml -f docker-compose.expose.yaml up -d --wait
	@echo "健康检查： http://127.0.0.1:8080/health"

down: ## 停止并清理容器/网络/卷（叠加过 expose 也能按项目名一并清理）
	docker compose -f docker-compose.yaml -f docker-compose.expose.yaml down -v --remove-orphans

logs: ## 跟随默认形态的服务日志
	docker compose -f docker-compose.yaml logs -f --tail=100

verify: ## 一键端到端验收（Windows 走 scripts/verify.ps1，其他平台走 scripts/verify.sh）
	$(VERIFY_CMD)

clean: ## 清理构建产物与本地临时文件
	rm -rf $(BIN_DIR) dist out.json coverage.out coverage.html
