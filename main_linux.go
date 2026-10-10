//go:build linux && amd64

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	mountDir = "/mnt/tiny_tmp"
	image    = "/var/tmp/ebpf-enospc.img"
	victim   = "fill.bin"
	MiB      = 1024 * 1024
)

func identity(s unix.Stat_t) fileIdentity {
	return fileIdentity{
		Inode: s.Ino, Major: unix.Major(s.Dev), Minor: unix.Minor(s.Dev),
		Links: s.Nlink, Regular: s.Mode&unix.S_IFMT == unix.S_IFREG,
		RootOwned: s.Uid == 0, Blocks: s.Blocks,
	}
}

func checkRoot(fd int) error {
	canonical, err := filepath.EvalSymlinks(mountDir)
	if err != nil || canonical != mountDir {
		return fmt.Errorf("mount path must exist without symlinks")
	}
	var root, current unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil {
		return err
	}
	if err := unix.Lstat(mountDir, &current); err != nil {
		return err
	}
	if root.Dev != current.Dev || root.Ino != current.Ino || root.Uid != 0 || root.Mode&07777 != 0700 {
		return fmt.Errorf("mount directory changed or is not root-owned mode 0700")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC || fs.Bsize <= 0 || fs.Blocks*uint64(fs.Bsize) > 64*MiB {
		return fmt.Errorf("expected the dedicated ext4 filesystem, no larger than 64 MiB")
	}
	dev := fmt.Sprintf("%d:%d", unix.Major(root.Dev), unix.Minor(root.Dev))
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 6 && f[2] == dev && f[3] == "/" && f[4] == mountDir {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("dedicated mount missing from this agent's mount namespace")
	}
	backing, err := os.ReadFile("/sys/dev/block/" + dev + "/loop/backing_file")
	if err != nil {
		return fmt.Errorf("mount is not a loop device: %w", err)
	}
	if strings.TrimPrefix(strings.TrimSpace(string(backing)), "/") != strings.TrimPrefix(image, "/") {
		return fmt.Errorf("unexpected loop backing file")
	}
	var img unix.Stat_t
	if err := unix.Lstat(image, &img); err != nil {
		return err
	}
	if img.Mode&unix.S_IFMT != unix.S_IFREG || img.Uid != 0 || img.Mode&07777 != 0600 || img.Size != 64*MiB || img.Nlink != 1 {
		return fmt.Errorf("backing image must be a root-owned 64 MiB regular file, mode 0600, one link")
	}
	return nil
}

func freeBytes(fd int) (uint64, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return 0, err
	}
	return fs.Bavail * uint64(fs.Bsize), nil
}

func removeVictim(fd int, e event) error {
	fileFD, err := unix.Openat(fd, victim, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fileFD)
	var s, root unix.Stat_t
	if err := unix.Fstat(fileFD, &s); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &root); err != nil {
		return err
	}
	if s.Dev != root.Dev {
		return fmt.Errorf("fill.bin is on a different device")
	}
	if err := matchVictim(e, identity(s)); err != nil {
		return err
	}
	available, err := freeBytes(fd)
	if err != nil {
		return err
	}
	if available > 2*MiB {
		return fmt.Errorf("filesystem is no longer nearly full (%d bytes available)", available)
	}
	log.Printf("DIAGNOSE device=%d:%d inode=%d available=%d allocated=%d", e.Major, e.Minor, e.Inode, available, s.Blocks*512)
	// Keep the inode alive while checking its name again, preventing inode reuse.
	var named unix.Stat_t
	if err := unix.Fstatat(fd, victim, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := matchVictim(e, identity(named)); err != nil {
		return err
	}
	if err := unix.Unlinkat(fd, victim, 0); err != nil {
		return err
	}
	log.Printf("ACT removed=%s/%s", mountDir, victim)
	return nil
}

func verifyWrite(fd int) (err error) {
	const name = ".verify-write"
	f, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, unix.Close(f), unix.Unlinkat(fd, name, 0))
	}()
	buf := make([]byte, MiB)
	for len(buf) > 0 {
		n, err := unix.Write(f, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("verification write made no progress")
		}
		buf = buf[n:]
	}
	return unix.Fsync(f)
}

func heal(fd int, e event) error {
	log.Printf("DETECT pid=%d tid=%d comm=dd errno=ENOSPC device=%d:%d inode=%d", e.PIDTGID>>32, uint32(e.PIDTGID), e.Major, e.Minor, e.Inode)
	if err := checkRoot(fd); err != nil {
		return err
	}
	if err := removeVictim(fd, e); err != nil {
		return err
	}
	// Unlinked data is reclaimed only after dd and the agent close their references.
	deadline := time.Now().Add(3 * time.Second)
	for {
		available, err := freeBytes(fd)
		if err != nil {
			return err
		}
		if available >= 8*MiB {
			if err := verifyWrite(fd); err != nil {
				return fmt.Errorf("VERIFY write/fsync failed: %w", err)
			}
			log.Printf("VERIFY OK available=%d write=1048576 fsync=OK", available)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("VERIFY timeout: only %d bytes available; an open descriptor may retain the deleted file", available)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func run() error {
	object := flag.String("bpf", "./enospc.bpf.o", "compiled eBPF object")
	flag.Parse()
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root")
	}
	fd, err := unix.Open(mountDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := checkRoot(fd); err != nil {
		return err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("another agent holds the mount lock: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("raise memlock: %w", err)
	}
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		return fmt.Errorf("BPF ring buffer unavailable (upstream requires Linux 5.8+): %w", err)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("kernel BTF required: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return fmt.Errorf("read BPF object: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF (verifier log): %+v", err)
	}
	defer collection.Close()
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return err
	}
	defer reader.Close()
	ret, err := link.Kretprobe("vfs_write", collection.Programs["write_exit"], nil)
	if err != nil {
		return fmt.Errorf("attach kretprobe: %w", err)
	}
	defer ret.Close()
	entry, err := link.Kprobe("vfs_write", collection.Programs["write_enter"], nil)
	if err != nil {
		return fmt.Errorf("attach kprobe: %w", err)
	}
	defer entry.Close()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-stop:
			reader.Close()
		case <-done:
		}
	}()
	log.Printf("READY monitoring vfs_write; cleanup whitelist=%s/%s", mountDir, victim)
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		e, err := decodeEvent(record.RawSample)
		if err != nil {
			log.Printf("SKIP %v", err)
			continue
		}
		if err := heal(fd, e); err != nil {
			log.Printf("HEAL FAILED/SKIPPED: %v", err)
		}
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
