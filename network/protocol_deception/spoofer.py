"""
PHANTOMNET — Protocol Spoofer
Linux: raw AF_PACKET socket ARP injection
Other: simulation/logging mode
"""

import asyncio
import platform
import socket
import struct
from typing import Optional

from utils.logger import setup_logger
from core.ai_engine.topology_generator import FakeTopology

IS_LINUX = platform.system() == "Linux"
ETH_P_ARP   = 0x0806
ARPOP_REPLY = 2


def _get_iface_mac(iface: str) -> bytes:
    if not IS_LINUX:
        return b"\x00\x0c\x29\xaa\xbb\xcc"
    import fcntl
    SIOCGIFHWADDR = 0x8927
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sH14s", iface.encode(), 0, b"\x00" * 14)
        return fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)[18:24]
    finally:
        s.close()


def _build_arp_reply(sender_mac, sender_ip, target_mac, target_ip) -> bytes:
    eth = struct.pack("!6s6sH", target_mac, sender_mac, ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, ARPOP_REPLY,
        sender_mac, socket.inet_aton(sender_ip),
        target_mac, socket.inet_aton(target_ip),
    )
    return eth + arp


def _get_interfaces() -> list:
    """List available network interfaces on Linux."""
    interfaces = []
    try:
        import os
        net_path = "/sys/class/net"
        if os.path.isdir(net_path):
            interfaces = os.listdir(net_path)
    except Exception:
        pass
    return interfaces


class ProtocolSpoofer:
    def __init__(self, config: dict):
        self.config    = config
        self.logger    = setup_logger("ProtocolSpoofer", config.get("log_level", "INFO"))
        self.interface = config.get("interface", "eth0")
        self.arp_enabled = config.get("arp_deception", True) and IS_LINUX
        self._raw_sock: Optional[socket.socket] = None
        self._running  = False
        self._active_topologies: dict[str, FakeTopology] = {}
        self._lock     = asyncio.Lock()

        if IS_LINUX:
            available = _get_interfaces()
            if available and self.interface not in available:
                self.logger.warning(
                    f"[ProtocolSpoofer] Interface '{self.interface}' not found. "
                    f"Available: {available}. Update config/phantomnet.yaml."
                )
        else:
            self.logger.warning(
                "[ProtocolSpoofer] Non-Linux — ARP injection disabled (logging mode)."
            )

    async def start(self):
        self._running = True
        if self.arp_enabled:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._open_raw_socket)
        self.logger.info("[ProtocolSpoofer] Started.")

    def _open_raw_socket(self):
        try:
            self._raw_sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP)
            )
            self._raw_sock.bind((self.interface, 0))
            self.logger.info(f"[ProtocolSpoofer] Raw ARP socket opened on {self.interface}.")
        except PermissionError:
            self.logger.error(
                "[ProtocolSpoofer] Permission denied — run with sudo."
            )
        except OSError as e:
            self.logger.error(f"[ProtocolSpoofer] Socket error: {e}")

    async def apply_topology(self, topology: FakeTopology, attacker_ip: str):
        async with self._lock:
            self._active_topologies[attacker_ip] = topology

        if IS_LINUX and self._raw_sock:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, self._send_arp_topology, topology, attacker_ip
            )
        else:
            self.logger.info(
                f"[ProtocolSpoofer] [SIM] Would inject {len(topology.hosts)} "
                f"ARP entries toward {attacker_ip}"
            )

        self.logger.info(
            f"[ProtocolSpoofer] Topology applied → {attacker_ip}: "
            f"{len(topology.hosts)} fake hosts."
        )

    def _send_arp_topology(self, topology: FakeTopology, attacker_ip: str):
        try:
            iface_mac = _get_iface_mac(self.interface)
        except Exception as e:
            self.logger.warning(f"[ProtocolSpoofer] Cannot get MAC: {e}")
            return
        broadcast = b"\xff\xff\xff\xff\xff\xff"
        for host in topology.hosts:
            try:
                fake_mac = bytes.fromhex(host.mac.replace(":", ""))
                pkt = _build_arp_reply(fake_mac, host.ip, broadcast, attacker_ip)
                self._raw_sock.send(pkt)
            except Exception as e:
                self.logger.debug(f"[ProtocolSpoofer] ARP error {host.ip}: {e}")

    async def stop(self):
        self._running = False
        if self._raw_sock:
            self._raw_sock.close()
        # Detach eBPF XDP on shutdown
        if IS_LINUX:
            import subprocess
            try:
                subprocess.run(
                    ["ip", "link", "set", "dev", self.interface, "xdp", "off"],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        self.logger.info("[ProtocolSpoofer] Stopped.")
