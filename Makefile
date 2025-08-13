# compile ebpf program

BUILD_DIR = build
INCLUDE_DIR = include
SCHEDULERS := cgroup_fair

all: $(BUILD_DIR)/$(SCHEDULERS).bpf.o $(BUILD_DIR)/$(SCHEDULERS).bpf.skel.h $(BUILD_DIR)/$(SCHEDULERS)

$(BUILD_DIR)/vmlinux.h:
	@mkdir -p $(BUILD_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/%.bpf.o: %.bpf.c $(BUILD_DIR)/vmlinux.h
	@mkdir -p $(BUILD_DIR)
	clang -Wall -target bpf -O2 -g -I$(BUILD_DIR) -I$(INCLUDE_DIR) -c $< -o $@

$(BUILD_DIR)/%.bpf.skel.h: $(BUILD_DIR)/%.bpf.o
	@echo "Generating skeleton header for $<"
	bpftool gen skeleton $< > $@

$(BUILD_DIR)/%: %.c $(BUILD_DIR)/%.bpf.skel.h
	@mkdir -p $(BUILD_DIR)
	clang -Wall -O2 -g -I$(BUILD_DIR) -I$(INCLUDE_DIR) -o $@ $< -lbpf

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean
