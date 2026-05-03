"""
PHANTOMNET — Graph Manager (Cross-Platform)
Discovers and maintains the real network topology baseline.
"""

import asyncio
import ipaddress
import platform
import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional

from utils.logger import setup_logger

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class RealHost:
    ip: str
    mac: str
    hostname: str
    open_ports: list = field(default_factory=list)
    is_gateway: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "open_ports": self.open_ports,
            "is_gateway": self.is_gateway,
        }


class GraphManager:
    def __init__(self, config: dict):
        self.config = config
        self.logger = setup_logger("GraphManager", config.get("log_level", "INFO"))
        self.network_cidr = config["network_cidr"]
        self.network = ipaddress.ip_network(self.network_cidr, strict=False)
        self._real_hosts: dict[str, RealHost] = {}
        self._lock = asyncio.Lock()

    async def discover_real_topology(self):
        self.logger.info(f"[GraphManager] Discovering topology on {self.network_cidr}...")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._arp_scan)
        self.logger.info(
            f"[GraphManager] Discovery complete: {len(self._real_hosts)} real hosts found."
        )

    def _arp_scan(self):
        """Read ARP cache — works on both Windows and Linux."""
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True, text=True, timeout=10
                )
                # Windows arp -a format: "  192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                        ip = parts[0]
                        mac = parts[1].replace("-", ":") if len(parts) > 1 else "00:00:00:00:00:00"
                        self._add_if_in_network(ip, mac)
            else:
                result = subprocess.run(
                    ["arp", "-n"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                        ip = parts[0]
                        mac = parts[2] if parts[2] != "(incomplete)" else "00:00:00:00:00:00"
                        self._add_if_in_network(ip, mac)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.warning(f"[GraphManager] ARP scan failed: {e}")

    def _add_if_in_network(self, ip: str, mac: str):
        try:
            addr = ipaddress.ip_address(ip)
            if addr in self.network:
                self._real_hosts[ip] = RealHost(ip=ip, mac=mac, hostname="")
        except ValueError:
            pass

    def is_real_host(self, ip: str) -> bool:
        return ip in self._real_hosts

    def real_node_count(self) -> int:
        return len(self._real_hosts)

    def get_real_ips(self) -> list:
        return list(self._real_hosts.keys())

    def get_real_host(self, ip: str) -> Optional[RealHost]:
        return self._real_hosts.get(ip)

    async def add_host(self, ip: str, mac: str, hostname: str = ""):
        async with self._lock:
            self._real_hosts[ip] = RealHost(ip=ip, mac=mac, hostname=hostname)

    def to_dict(self) -> dict:
        return {
            "network_cidr": self.network_cidr,
            "real_hosts": [h.to_dict() for h in self._real_hosts.values()],
        }
