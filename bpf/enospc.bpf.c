#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u64 pid_tgid;
    __u64 inode;
    __u32 major;
    __u32 minor;
    char comm[16];
};

_Static_assert(sizeof(struct event) == 40, "Go event ABI must match");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct event);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* The return probe cannot recover the original file argument. */
SEC("kprobe/vfs_write")
int BPF_KPROBE(write_enter, struct file *file)
{
    struct event e = {};
    bpf_get_current_comm(e.comm, sizeof(e.comm));
    if (e.comm[0] != 'd' || e.comm[1] != 'd' || e.comm[2] != 0)
        return 0;

    e.pid_tgid = bpf_get_current_pid_tgid();
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    __u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    e.inode = BPF_CORE_READ(inode, i_ino);
    /* Kernel dev_t uses 20 minor bits, unlike userspace stat.st_dev. */
    e.major = dev >> 20;
    e.minor = dev & ((1U << 20) - 1);
    bpf_map_update_elem(&pending, &e.pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(write_exit, long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct event *saved = bpf_map_lookup_elem(&pending, &key);
    if (!saved)
        return 0;

    if (ret == -28) { /* -ENOSPC */
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            *e = *saved;
            bpf_ringbuf_submit(e, 0);
        }
        /* shortcut: full buffers can drop events; add counters for production. */
    }
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
