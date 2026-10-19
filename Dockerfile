# 基线镜像刻意选本地已有的 tag —— 实测 go1.22.12 linux/amd64 可用。
# 配合 scratch 运行时 + vendor/ 依赖，整条构建链 **零镜像拉取、零网络依赖**。
#
# 刻意不写 `# syntax=docker/dockerfile:1.7`：那行会强制拉取一个 frontend 镜像，破坏"零拉取"。
# `RUN --mount=type=cache` 由 BuildKit 内置 frontend 直接支持，无需该指令。
ARG GO_VERSION=1.22
ARG GO_FLAVOR=alpine3.20

# ---- 源码层：依赖清单 + vendor + 源码分区 COPY，改代码不失效依赖层 ----
FROM golang:${GO_VERSION}-${GO_FLAVOR} AS src
WORKDIR /src
# GOTOOLCHAIN=local 关键：禁止 Go 因 go.mod 版本去联网下载新工具链。
# GOFLAGS=-mod=vendor 关键：只从仓库内已提交的 vendor/ 取依赖，构建期不访问 proxy.golang.org。
ENV GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/
COPY rules/ rules/
COPY testdata/ testdata/
# 补充（§6.1 清单之外，但必须）：模块根还有 Go 源码 builtin.go（package bannerd），
# 它用 `//go:embed rules/*.yaml` 承载内置规则包，且 internal/rules 直接 import 这个根包。
# go:embed 不允许引用父目录（".."），规则数据因此只在仓库根 rules/ 存一份；根包必须一起
# COPY，否则 `go build ./cmd/server` 会失败（package github.com/aicoding1019/bannerd: no Go files）。
COPY *.go ./

# ---- 校验层：vet + 单测（CI 用 `docker build --target test .`）----
FROM src AS test
RUN --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./...

# ---- 编译层：静态、可复现、版本注入 ----
FROM src AS build
ARG VERSION=dev
ARG GIT_SHA=unknown
# -trimpath -buildvcs=false 让产物可复现；netgo/osusergo 让二进制不依赖 libc/系统用户库，
# 因此才能在 scratch 里直接运行；-s -w 去掉符号表与调试信息。
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
