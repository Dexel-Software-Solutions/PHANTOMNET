# PHANTOMNET — Makefile
# Supports: Kali Linux, Ubuntu, Debian, ParrotOS, Arch

.PHONY: all install build-go build-ebpf test run clean uninstall check-deps

all: check-deps build-go build-ebpf

check-deps:
	@echo "[*] Checking dependencies..."
	@command -v python3  >/dev/null || (echo "[!] python3 not found" && exit 1)
	@command -v go       >/dev/null || echo "[!] go not found — packet engine will use simulation mode"
	@command -v clang    >/dev/null || echo "[!] clang not found — eBPF module will be skipped"
	@command -v openssl  >/dev/null || echo "[!] openssl not found — TLS cert generation may fail"
	@echo "[+] Dependency check complete."

install:
	@if [ "$$(id -u)" -ne 0 ]; then echo "[ERROR] Run: sudo make install"; exit 1; fi
	bash scripts/install.sh

build-go:
	@echo "[*] Building Go packet engine..."
	@command -v go >/dev/null || (echo "[!] Go not installed. Install: apt install golang-go"; exit 0)
	mkdir -p network/packet_engine/bin
	cd network/packet_engine && go mod tidy 2>/dev/null; go build -o bin/pktengine main.go
	@echo "[+] Built: network/packet_engine/bin/pktengine"

build-ebpf:
	@echo "[*] Building eBPF module..."
	@command -v clang >/dev/null || (echo "[!] clang not installed. Install: apt install clang libbpf-dev"; exit 0)
	cd network/ebpf && make
	@echo "[+] Built: network/ebpf/phantomnet_filter.o"

attach-ebpf:
	@IFACE=$$(grep "^interface:" config/phantomnet.yaml | awk '{print $$2}' | tr -d '"'); \
	echo "[*] Attaching eBPF to $$IFACE..."; \
	ip link set dev $$IFACE xdp obj network/ebpf/phantomnet_filter.o sec xdp_filter && \
	echo "[+] eBPF attached to $$IFACE" || echo "[!] eBPF attach failed"

detach-ebpf:
	@IFACE=$$(grep "^interface:" config/phantomnet.yaml | awk '{print $$2}' | tr -d '"'); \
	ip link set dev $$IFACE xdp off && echo "[+] eBPF detached from $$IFACE"

test:
	@echo "[*] Running unit tests..."
	python3 tests/test_fingerprinter.py
	python3 tests/test_topology_generator.py
	@echo "[+] All tests passed."

run:
	@if [ "$$(id -u)" -ne 0 ]; then echo "[ERROR] Run: sudo make run"; exit 1; fi
	python3 phantomnet.py --config config/phantomnet.yaml

run-debug:
	@if [ "$$(id -u)" -ne 0 ]; then echo "[ERROR] Run: sudo make run-debug"; exit 1; fi
	python3 phantomnet.py --config config/phantomnet.yaml --log-level DEBUG

clean:
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f network/packet_engine/bin/pktengine
	rm -f network/ebpf/phantomnet_filter.o
	rm -f logs/*.log logs/*.json 2>/dev/null || true
	@echo "[+] Clean done."

uninstall:
	@IFACE=$$(grep "^interface:" config/phantomnet.yaml 2>/dev/null | awk '{print $$2}' | tr -d '"' || echo "eth0"); \
	ip link set dev $$IFACE xdp off 2>/dev/null || true
	@echo "[+] PHANTOMNET uninstalled."
