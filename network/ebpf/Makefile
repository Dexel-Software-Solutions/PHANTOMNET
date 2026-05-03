# PHANTOMNET eBPF Makefile
CC     = clang
TARGET = phantomnet_filter.o
SRC    = phantomnet_filter.c
IFACE  ?= eth0

.PHONY: all clean attach detach

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -O2 -target bpf -D__BPF_TRACING__ \
		-I/usr/include/bpf \
		-c $(SRC) -o $(TARGET)
	@echo "[eBPF] Compiled: $(TARGET)"

attach: $(TARGET)
	ip link set dev $(IFACE) xdp obj $(TARGET) sec xdp_filter
	@echo "[eBPF] Attached to $(IFACE)"

detach:
	ip link set dev $(IFACE) xdp off
	@echo "[eBPF] Detached from $(IFACE)"

clean:
	rm -f $(TARGET)
