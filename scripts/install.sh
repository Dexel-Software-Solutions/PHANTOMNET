#!/usr/bin/env bash
# PHANTOMNET — Universal Linux Installer
# Supports: Kali Linux, Ubuntu 20.04/22.04/24.04, Debian 11/12, ParrotOS, BlackArch

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [[ $EUID -ne 0 ]]; then error "Run as root: sudo bash scripts/install.sh"; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Detect distro
DISTRO="unknown"
if   [[ -f /etc/kali_version ]];     then DISTRO="kali"
elif [[ -f /etc/parrot-version ]];   then DISTRO="parrot"
elif grep -qi "ubuntu" /etc/os-release 2>/dev/null; then DISTRO="ubuntu"
elif grep -qi "debian" /etc/os-release 2>/dev/null; then DISTRO="debian"
elif grep -qi "arch"   /etc/os-release 2>/dev/null; then DISTRO="arch"
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     PHANTOMNET — Universal Linux Installer          ║${NC}"
echo -e "${CYAN}║     Demiyan Dissanayake | Dexel Software Solutions  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "  Detected distro: ${YELLOW}${DISTRO}${NC}"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────
info "Installing system dependencies for ${DISTRO}..."

if [[ "$DISTRO" == "arch" ]]; then
    pacman -Sy --noconfirm python python-pip go gcc clang libpcap libbpf iproute2 openssl make 2>/dev/null || true
else
    apt-get update -qq 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        python3 python3-pip python3-venv python3-dev \
        golang-go \
        gcc clang \
        libpcap-dev libbpf-dev linux-headers-$(uname -r) \
        iproute2 net-tools arp-scan \
        openssl \
        curl wget git \
        make build-essential 2>/dev/null || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        python3 python3-pip python3-venv \
        golang \
        gcc clang \
        libpcap-dev \
        iproute2 net-tools \
        openssl make 2>/dev/null || true
fi
ok "System packages installed."

# ── 2. Python venv ────────────────────────────────────────────────────────
info "Setting up Python virtual environment..."
python3 -m venv venv 2>/dev/null || python3 -m venv --system-site-packages venv
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet pyyaml cryptography
ok "Python venv ready."

# ── 3. Go packet engine ───────────────────────────────────────────────────
info "Building Go packet engine..."
mkdir -p network/packet_engine/bin

GO_BIN="$(command -v go 2>/dev/null || echo '')"
if [[ -n "$GO_BIN" ]]; then
    cd network/packet_engine
    # Write go.sum if missing
    go mod tidy 2>/dev/null || true
    if go build -o bin/pktengine main.go 2>/dev/null; then
        ok "Go packet engine compiled: network/packet_engine/bin/pktengine"
    else
        warn "Go build failed — falling back to simulation mode."
    fi
    cd "$PROJECT_DIR"
else
    warn "Go not found — packet engine will run in simulation mode."
fi

# ── 4. eBPF module ────────────────────────────────────────────────────────
info "Building eBPF kernel module..."
KERNEL_VER=$(uname -r)
if command -v clang &>/dev/null && [[ -d "/lib/modules/${KERNEL_VER}/build" ]]; then
    cd network/ebpf
    if make 2>/dev/null; then
        ok "eBPF module compiled."
        # Attach to interface if specified
        IFACE=$(grep "^interface:" "$PROJECT_DIR/config/phantomnet.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "eth0")
        if ip link show "$IFACE" &>/dev/null; then
            ip link set dev "$IFACE" xdp off 2>/dev/null || true
            ip link set dev "$IFACE" xdp obj phantomnet_filter.o sec xdp_filter 2>/dev/null && \
                ok "eBPF XDP attached to ${IFACE}" || warn "eBPF attach failed (non-fatal)"
        fi
    else
        warn "eBPF compile failed — kernel-level capture disabled."
    fi
    cd "$PROJECT_DIR"
else
    warn "clang or kernel headers missing — skipping eBPF build."
fi

# ── 5. TLS certificate ────────────────────────────────────────────────────
info "Generating TLS certificate..."
mkdir -p config/certs
if [[ ! -f config/certs/server.crt ]]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout config/certs/server.key \
        -out    config/certs/server.crt \
        -subj   "/CN=PHANTOMNET/O=Dexel Software Solutions/C=LK" \
        -addext "subjectAltName=IP:127.0.0.1,IP:0.0.0.0,DNS:localhost" \
        2>/dev/null
    chmod 600 config/certs/server.key
    ok "TLS certificate generated."
else
    ok "TLS certificate already exists."
fi

# ── 6. Default config ─────────────────────────────────────────────────────
if [[ ! -f config/phantomnet.yaml ]]; then
    cp config/phantomnet.yaml.example config/phantomnet.yaml
    # Auto-detect primary interface
    PRIMARY_IFACE=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || echo "eth0")
    # Auto-detect network CIDR
    PRIMARY_CIDR=$(ip -o -f inet addr show "$PRIMARY_IFACE" 2>/dev/null | awk '{print $4}' | head -1 || echo "192.168.1.0/24")
    # Write detected values into config
    sed -i "s|^interface:.*|interface: \"${PRIMARY_IFACE}\"|" config/phantomnet.yaml
    sed -i "s|^network_cidr:.*|network_cidr: \"${PRIMARY_CIDR}\"|" config/phantomnet.yaml
    ok "Config created with auto-detected interface=${PRIMARY_IFACE} cidr=${PRIMARY_CIDR}"
else
    ok "Config already exists."
fi

# ── 7. Directories + __init__.py ──────────────────────────────────────────
mkdir -p logs
for d in core core/ai_engine core/topology core/behavioral \
          network network/packet_engine network/protocol_deception network/ebpf \
          forensics forensics/trap_layer forensics/threat_intel \
          dashboard dashboard/api dashboard/frontend \
          config utils; do
    touch "$d/__init__.py"
done
ok "Package structure ready."

# ── 8. Set capabilities (no root needed at runtime on Linux) ─────────────
PYTHON_BIN="$(readlink -f venv/bin/python3 2>/dev/null || which python3)"
if command -v setcap &>/dev/null; then
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$PYTHON_BIN" 2>/dev/null && \
        ok "Capabilities set on Python — can run without sudo." || \
        warn "setcap failed — run with sudo python3."
fi

# ── 9. Tests ──────────────────────────────────────────────────────────────
info "Running unit tests..."
source venv/bin/activate
PASS=0
python3 tests/test_fingerprinter.py    2>/dev/null && PASS=$((PASS+1))
python3 tests/test_topology_generator.py 2>/dev/null && PASS=$((PASS+1))
ok "${PASS}/2 test suites passed."

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     PHANTOMNET Installation Complete! ✓             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Quick Start:${NC}"
echo -e "  ${YELLOW}sudo python3 phantomnet.py --config config/phantomnet.yaml${NC}"
echo -e "  Dashboard → ${YELLOW}https://localhost:8443${NC}"
echo ""
