#!/usr/bin/env bash
set -euo pipefail
umask 077

image=/var/tmp/ebpf-enospc.img
mount_dir=/mnt/tiny_tmp

[[ $(id -u) == 0 ]] || { echo '请使用 sudo bash setup-loop.sh' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo '需要 Linux x86_64' >&2; exit 1; }
for cmd in dd mkfs.ext4 mount mountpoint findmnt readlink df awk; do
    command -v "$cmd" >/dev/null || { echo "缺少命令: $cmd" >&2; exit 1; }
done
[[ $(readlink -f /var/tmp) == /var/tmp && $(readlink -f /mnt) == /mnt ]] || {
    echo '/var/tmp 或 /mnt 不能是符号链接' >&2; exit 1;
}
[[ ! -e "$image" && ! -L "$image" ]] || { echo "拒绝覆盖已有文件: $image" >&2; exit 1; }
[[ ! -e "$mount_dir" && ! -L "$mount_dir" ]] || { echo "拒绝复用已有目录: $mount_dir" >&2; exit 1; }
available_kib=$(df -Pk /var/tmp | awk 'NR == 2 { print $4 }')
if [[ ! "$available_kib" =~ ^[0-9]+$ ]] || (( available_kib < 128 * 1024 )); then
    echo '/var/tmp 所在文件系统至少需要 128 MiB 可用空间' >&2; exit 1;
fi

mkdir -m 0700 "$mount_dir"
dd if=/dev/zero of="$image" bs=1M count=64 conv=excl status=none
chmod 0600 "$image"
mkfs.ext4 -q -F -m 0 -L TINY_ENOSPC "$image"
mount -t ext4 -o loop,nodev,nosuid,noexec "$image" "$mount_dir"
chmod 0700 "$mount_dir"
mountpoint -q "$mount_dir"
findmnt --mountpoint "$mount_dir"
echo 'READY: 已创建 64 MiB 镜像及独立 ext4 回环挂载。'
echo '停止 Agent 后卸载；安装或挂载失败时先检查实际挂载状态再清理残留文件。'
