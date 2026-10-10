CLANG ?= clang
BPFTOOL ?= bpftool
GO ?= go

.PHONY: all test
all: enospc.bpf.o agent

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

enospc.bpf.o: bpf/enospc.bpf.c bpf/vmlinux.h
	$(CLANG) -O2 -g -target bpfel -D__TARGET_ARCH_x86 -Wall -Werror -Ibpf -c $< -o $@

agent: main_linux.go event.go go.mod go.sum
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o $@ .

go.sum: go.mod
	$(GO) mod tidy

test:
	$(GO) test ./...
