# EBPF_OBJ = rawsyshook.o
# VMLINUX_H = vmlinux.h
# SKEL = loader.skel.h
# LOADER_OBJ = loader.o

# .PHONY: ebpf vmlinux skeleton loader clean

# ebpf: $(EBPF_OBJ)

# $(EBPF_OBJ): rawsyshook.c
# 	sudo clang -O2 -target bpf -c rawsyshook.c -o rawsyshook.o

# vmlinux: $(VMLINUX_H)

# $(VMLINUX_H):
# 	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# skeleton: $(EBPF_OBJ)
# 	sudo bpftool gen skeleton rawsyshook.o name loader > loader.skel.h

# loader: loader.c $(SKEL)
# 	clang loader.c -lbpf -o loader.o
# clean:
# 	rm -f $(EBPF_OBJ) $(VMLINUX_H) $(SKEL) $(LOADER_OBJ)

# 실행 파일 이름
APP = sys_enter_and_out

# 소스 파일 이름
EBPF_SRC = $(APP).bpf.c
USER_SRC = $(APP).c

# 생성될 파일 이름
EBPF_OBJ = $(EBPF_SRC:.c=.o)
USER_EXEC = $(USER_SRC:.c=)
SKEL_H = $(APP).skel.h
VMLINUX_H = vmlinux.h

# 컴파일러
CC ?= clang
BPFTOOL ?= bpftool

# BPF 컴파일 옵션 (aarch64 환경 최종본)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_SRC := ~/linux-kernel
# BPF_CFLAGS = -nostdinc -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
             -isystem /usr/include/bpf \
             -isystem $(KERNEL_SRC)/include \
             -isystem $(KERNEL_SRC)/include/uapi \
             -isystem $(KERNEL_SRC)/include/generated/uapi \
             -isystem $(KERNEL_SRC)/arch/$(ARCH)/include \
             -isystem $(KERNEL_SRC)/arch/$(ARCH)/include/uapi \
             -isystem $(KERNEL_SRC)/arch/$(ARCH)/include/generated

.PHONY: all run clean

all: $(USER_EXEC)

run: all
	sudo ./$(USER_EXEC)

$(USER_EXEC): $(USER_SRC) $(SKEL_H)
	$(CC) -g $(USER_SRC) -lbpf -lelf -o $(USER_EXEC)
# -g 추가

$(SKEL_H): $(EBPF_OBJ)
	sudo $(BPFTOOL) gen skeleton $< > $@

$(EBPF_OBJ): $(EBPF_SRC) $(VMLINUX_H)
	sudo clang -O2 -target bpf -g -c $< -o $@ 

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(EBPF_OBJ) $(VMLINUX_H) $(SKEL_H) $(USER_EXEC)