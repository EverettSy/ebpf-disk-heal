# eBPF 磁盘空间自愈演示

链路：`vfs_write 返回 -ENOSPC → ring buffer → Go Agent → 核对设备与 inode → 删除测试文件 → 实际写入验证`。

这是故障发生后的、规则驱动的演示。仅处理 `/mnt/tiny_tmp/fill.bin`，不会扫描目录或删除其他文件；不会自动重试原来失败的 dd。64 MiB 镜像预先分配在系统盘，只消耗固定的约 64 MiB，不会用 dd 填满系统盘。

## 1. 准备环境：必须先修正内核前提

**CentOS 7.9 默认 3.10 内核不能运行此 ring buffer 版本。** 上游 `BPF_MAP_TYPE_RINGBUF` 自 Linux 5.8 才提供；这个实现还使用 CO-RE，因此必须有 `/sys/kernel/btf/vmlinux`。仅安装 Go、BCC 或 Clang 不会补齐内核功能。

若必须保留 CentOS 7.9 用户态，请在测试虚拟机里先安装并启动经验证的现代 x86_64 内核（例如支持所需配置的 5.15 / 6.6），以及 Clang 11+、libbpf 开发头文件和 bpftool。内核来源、安装方法和引导设置依镜像而异，本项目不修改内核或启动项。CentOS 7 的默认旧 Clang 也不能直接承担这里的编译。

内核至少需要：`CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_EVENTS=y`、`CONFIG_KPROBES=y`、`CONFIG_KPROBE_EVENTS=y`、`CONFIG_DEBUG_INFO_BTF=y`，以及 loop 和 ext4 支持。还需允许 root 加载 BPF 和挂载文件系统，内核 lockdown/容器能力限制可能阻止操作。用完整测试虚拟机，Agent 和 dd 应在同一个挂载命名空间中运行。

检查：

```bash
uname -r
uname -m                        # x86_64
test -r /sys/kernel/btf/vmlinux
clang --version                 # 11+，且包含 BPF 后端
clang -print-targets | grep bpf
bpftool version
sudo bpftool feature probe kernel | grep -E 'ringbuf|kprobe'
go version                      # Go 1.22+；建议采用仍受维护的版本
```

更容易复现的构建/运行环境是现代 Linux。以 Ubuntu 24.04 x86_64 测试虚拟机为例，安装工具：

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev bpftool make golang-go e2fsprogs util-linux
```

CentOS 7.9 上的基础工具可以安装：

```bash
sudo yum install -y make e2fsprogs util-linux
```

此命令**不负责**安装现代内核、Go 或现代 LLVM/libbpf。CentOS 7 已于 2024-06-30 结束支持，原镜像源也可能不可用。Go 安装方法见官方文档；Cilium 依赖固定为 `v0.17.3`，用于保持此演示的 Go 1.22 兼容性，不表示它是最新版本。

也可以在现代 x86_64 Linux 构建机完成第 3、4 步，把 `agent`、`enospc.bpf.o` 和 `setup-loop.sh` 复制到已经启动现代内核的 CentOS 7.9 测试机。Agent 使用 `CGO_ENABLED=0`，运行时不依赖动态 libbpf；CO-RE 会依据目标内核 BTF 调整字段偏移。此方式仍要求目标机具备 BTF、ring buffer、可挂载的 loop/ext4 及可附着的 `vfs_write`。

## 2. 创建独立 64 MiB 分区

将本目录复制到目标 Linux，进入目录执行：

```bash
sudo bash setup-loop.sh
df -h /mnt/tiny_tmp
sudo losetup -j /var/tmp/ebpf-enospc.img
```

脚本先要求镜像所在文件系统至少有 128 MiB 可用空间，再使用真实分配的 64 MiB 文件、ext4、`-m 0`（无 root 预留块）及 loop 挂载。镜像权限为 root:0600，挂载根目录为 root:0700。若镜像或目录已存在，脚本会拒绝覆盖；检查旧实验后再清理。文件系统元数据会占用部分空间，可用空间小于 64 MiB。

## 3. 编译 eBPF 探针

```bash
make enospc.bpf.o
```

Makefile 从运行内核 BTF 生成 `bpf/vmlinux.h`，再编译探针。`kprobe/vfs_write` 保存 dd 写入文件的设备号、inode 和线程标识；`kretprobe/vfs_write` 在返回值为 `-28` 时上报 40 字节事件。这两个探针配对，避免仅凭进程名就误删文件。

## 4. 编译 Go Agent

```bash
go mod download
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o agent .
```

Agent 检查 ext4、独立挂载、固定 loop 镜像、容量和权限；再将事件设备号/inode 与白名单文件匹配。使用目录文件描述符和 `openat`/`unlinkat`，拒绝符号链接、硬链接、非普通文件及其他设备。只在剩余可用空间不超过 2 MiB 时执行删除。

删除后等待最多 3 秒，要求空间恢复到至少 8 MiB，再创建一个排他测试文件、写入 1 MiB、`fsync` 并删除它。文件仍被其他进程打开时，删除目录项不一定立即释放空间；验证失败会如实报错。

## 5. 启动监控

终端 A，在项目目录中执行：

```bash
make
sudo ./agent
```

看到 `READY monitoring vfs_write` 后才注入故障。`Ctrl+C` 或 SIGTERM 会关闭 ring buffer 并解除探针；不保留 pinned map。加载失败时打印错误；不要将未出现 READY 视为监控已启动。

## 6. 注入 ENOSPC

终端 B：

```bash
sudo dd if=/dev/zero of=/mnt/tiny_tmp/fill.bin bs=1M count=128 oflag=direct conv=excl
```

`oflag=direct` 避免仅在后续回写或 fsync 才暴露空间不足，使本实验在写路径上触发错误。`conv=excl` 防止覆盖既有文件。dd 的非零退出和 `No space left on device` 在此实验中是预期结果。

## 7. 观察自愈闭环

预期日志示意（不是本机实测记录；PID、inode、字节数以目标机为准）：

```text
READY monitoring vfs_write; cleanup whitelist=/mnt/tiny_tmp/fill.bin
DETECT pid=1234 tid=1234 comm=dd errno=ENOSPC device=7:0 inode=12
DIAGNOSE device=7:0 inode=12 available=0 allocated=...
ACT removed=/mnt/tiny_tmp/fill.bin
VERIFY OK available=... write=1048576 fsync=OK
```

终端 B 验收：

```bash
sudo test ! -e /mnt/tiny_tmp/fill.bin
df -h /mnt/tiny_tmp
sudo dd if=/dev/zero of=/mnt/tiny_tmp/recovery.bin bs=1M count=1 oflag=direct conv=excl,fsync
sudo rm -- /mnt/tiny_tmp/recovery.bin
```

这个验证文件不是 Agent 的清理目标。若要再次演示，等待上一轮 `VERIFY OK` 后重新运行故障命令。

## 停止及清理实验

先在终端 A 按 Ctrl+C；确认下面查询的 loop 设备与挂载源属于本实验，再卸载。镜像使用 `mount -o loop` 创建，现代 Linux 在正常卸载后通常会自动释放 loop 关联；若仍关联，用查询结果中的**实际设备名**执行 `losetup -d`，不要猜 loop 编号。

```bash
findmnt --mountpoint /mnt/tiny_tmp
sudo losetup -j /var/tmp/ebpf-enospc.img
sudo umount /mnt/tiny_tmp
sudo losetup -j /var/tmp/ebpf-enospc.img
# 若上一行仍显示关联，先 sudo losetup -d /dev/实际设备名
# 确认已卸载且 loop 已释放后：
sudo rm -- /var/tmp/ebpf-enospc.img
sudo rmdir -- /mnt/tiny_tmp
```

## 边界及排查

- 这不是提前按磁盘使用率清理，而是收到写失败事件后清理。生产环境应先定义可删除数据、保留期和容量策略，不能照搬为删除业务数据。
- 只覆盖 `vfs_write` 上 dd 的同步 ENOSPC，未覆盖 writev、io_uring、mmap 写回、fsync 错误、配额 EDQUOT 或其他进程。首次失败的写入不会被 eBPF 自动修复。
- ring buffer 满、LRU 记录淘汰或 kretprobe 漏采可能丢事件；本演示不提供生产级丢失统计和兜底巡检。
- 测试目录 root 专用；实验期间不要由另一个 root 进程替换文件或挂载。设备/inode 校验不提供对恶意 root 的隔离。
- 有 DETECT、无 ACT：检查 `HEAL FAILED/SKIPPED`，可能是别的磁盘、文件已替换、仍有较多空闲空间，或安全前提不满足。
- ACT 后 VERIFY 超时：检查是否有进程仍打开已删除文件，不要把 unlink 成功当作空间回收成功。
- 没有 DETECT：先检查 READY、内核功能及探针加载错误，并确认使用了给定的 direct I/O 故障命令。

参考：

- [Linux BPF ring buffer 文档](https://docs.kernel.org/bpf/ringbuf.html)
- [Linux v5.8 BPF UAPI（包含 RINGBUF）](https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h)
- [Cilium ebpf-go](https://github.com/cilium/ebpf)
- [Go 官方安装文档](https://go.dev/doc/install)
- [CentOS Linux 生命周期](https://www.centos.org/centos-linux/)

本项目的本地验证结果记录在 `VALIDATION.md`。完整 Linux 故障注入仍需在目标测试虚拟机执行。
