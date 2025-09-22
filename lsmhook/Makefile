EBPF_OBJ = lsm_path_unlink.o
EBPF_SRC = lsm_path_unlink.c
VMLINUX_H = vmlinux.h
SKEL_H = loader.skel.h
USERSPACE_OBJ = loadself_del_detect_loader.o
USERSPACE_SRC = self_del_detect_loader.c


.PHONY : ebpf vmlinux skeleton loader clean

ebpf : $(EBPF_OBJ)

$(EBPF_OBJ): $(EBPF_SEC)
	sudo clang -O2 -target bpf -g -c $(EBPF_SRC) -o $(EBPF_OBJ)

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

skeleton : $(EBPF_OBJ)
	sudo bpftool gen skeleton $(EBPF_OBJ) name loader > $(SKEL_H)

loader: $(USERSPACE_SRC) $(SKEL_H)
	clang $(USERSPACE_SRC) -lbpf -o $(USERSPACE_OBJ)

delebpf:
	rm -f $(EBPF_OBJ)

clean:
	rm -f $(EBPF_OBJ) $(VMLINUX_H) $(SKEL) $(USERSPACE_OBJ)