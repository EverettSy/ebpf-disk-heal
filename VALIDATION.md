# 验证记录（2026-10-10）

本地环境：macOS arm64。临时 Go 1.27.2 工具链从 Go 官方下载，压缩包 SHA-256 已与官方清单核对。

已通过：

- `shellcheck setup-loop.sh`。
- `bash -n setup-loop.sh`。
- `go test -v event.go event_test.go`：40 字节事件 ABI、异常长度拒绝，以及进程不符、其他设备、文件替换、缺失 inode、符号链接、硬链接、非 root 所有者、无已分配块这 8 类拒绝用例。
- `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o agent .`：Linux x86_64 Agent 交叉编译成功，产物为本目录的 `agent`。
- `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go vet ./...`：静态检查通过。

未验证：

- eBPF C 的 Linux 编译、CO-RE 重定位及内核 verifier 加载；本机 Clang 不含 BPF 后端，且没有 Linux 内核 BTF。
- 目标 CentOS 的内核/工具链安装、loop 挂载、真实 dd ENOSPC 注入、空间回收与写入恢复。
- 恶意 root 并发操作、生产负载下漏采/丢事件、其他写路径及业务进程自动重试。

README 中日志是预期示意，不是运行记录。请按 README 第 1 至 7 步在专用 Linux 测试虚拟机验收。
