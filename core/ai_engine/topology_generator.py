"""
PHANTOMNET — AI Topology Generator
Generates contextually convincing fake network topologies
using ML-driven fingerprint adaptation.
"""

import asyncio
import random
import ipaddress
import hashlib
from typing import Optional
from dataclasses import dataclass, field

from utils.logger import setup_logger


# ─── OS/Service fingerprint database (real world data) ──────────────────────
OS_PROFILES = {
    "windows_server_2022": {
        "ttl": 128,
        "open_ports": [135, 139, 445, 3389, 5985],
        "banners": {
            445: "Windows Server 2022",
            3389: "Microsoft Terminal Services",
        },
        "mac_prefix": ["00:0C:29", "00:50:56", "00:15:5D"],
    },
    "ubuntu_22": {
        "ttl": 64,
        "open_ports": [22, 80, 443, 8080],
        "banners": {
            22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            80: "Apache/2.4.54 (Ubuntu)",
        },
        "mac_prefix": ["52:54:00", "00:16:3E", "FA:16:3E"],
    },
    "cisco_ios": {
        "ttl": 255,
        "open_ports": [22, 23, 80, 161, 443],
        "banners": {
            23: "User Access Verification",
            22: "SSH-2.0-Cisco-1.25",
        },
        "mac_prefix": ["00:0A:8A", "00:1A:A2", "00:1C:57"],
    },
    "fortinet_fortigate": {
        "ttl": 64,
        "open_ports": [22, 443, 541, 8443],
        "banners": {443: "FortiGate HTTPS"},
        "mac_prefix": ["00:09:0F", "00:0B:86"],
    },
    "freebsd_13": {
        "ttl": 64,
        "open_ports": [22, 80, 443],
        "banners": {22: "SSH-2.0-OpenSSH_9.3 FreeBSD-20230719"},
        "mac_prefix": ["52:54:00", "00:16:3E"],
    },
}

SERVICES = {
    "web_server": {"ports": [80, 443, 8080, 8443], "os": ["ubuntu_22", "windows_server_2022"]},
    "database": {"ports": [3306, 5432, 1433, 27017], "os": ["ubuntu_22", "windows_server_2022"]},
    "file_server": {"ports": [445, 139, 2049], "os": ["windows_server_2022", "freebsd_13"]},
    "mail_server": {"ports": [25, 143, 465, 587, 993], "os": ["ubuntu_22"]},
    "vpn_gateway": {"ports": [1194, 1723, 500], "os": ["cisco_ios", "fortinet_fortigate"]},
    "router": {"ports": [22, 23, 80, 161], "os": ["cisco_ios"]},
    "workstation": {"ports": [135, 139, 3389], "os": ["windows_server_2022"]},
}


@dataclass
class FakeHost:
    ip: str
    mac: str
    os_profile: str
    services: list[str]
    open_ports: list[int]
    ttl: int
    banners: dict[int, str]
    hostname: str
    is_trap: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "os_profile": self.os_profile,
            "services": self.services,
            "open_ports": self.open_ports,
            "ttl": self.ttl,
            "banners": self.banners,
            "hostname": self.hostname,
            "is_trap": self.is_trap,
        }


@dataclass
class FakeTopology:
    attacker_ip: str
    hosts: list[FakeHost] = field(default_factory=list)
    subnet: str = ""
    gateway_ip: str = ""
    generation_id: str = ""

    def to_dict(self) -> dict:
        return {
            "attacker_ip": self.attacker_ip,
            "subnet": self.subnet,
            "gateway_ip": self.gateway_ip,
            "generation_id": self.generation_id,
            "hosts": [h.to_dict() for h in self.hosts],
        }


class TopologyGenerator:
    """
    AI-driven fake topology generator.
    Produces believable network topologies tailored to each attacker's TTPs.
    """

    def __init__(self, config: dict, graph_manager):
        self.config = config
        self.graph_manager = graph_manager
        self.logger = setup_logger("TopologyGenerator", config.get("log_level", "INFO"))
        self.network = ipaddress.ip_network(config["network_cidr"], strict=False)
        self.max_hosts = config.get("max_fake_hosts", 50)
        self.complexity = config.get("topology_complexity", "medium")
        self._attacker_topologies: dict[str, FakeTopology] = {}

        # Seed RNG deterministically per-attacker for reproducibility within session
        self._rng = random.Random()

    def _seed_for_attacker(self, attacker_ip: str, morph_round: int = 0):
        """Seed RNG based on attacker IP and morph round — different each morph."""
        seed_str = f"{attacker_ip}:{morph_round}"
        seed = int(hashlib.sha256(seed_str.encode()).hexdigest(), 16) % (2**32)
        self._rng.seed(seed)

    def _pick_fake_subnet(self) -> str:
        """Pick a plausible RFC-1918 subnet that differs from the real one."""
        real_cidr = str(self.network)
        candidates = [
            "10.10.20.0/24",
            "10.10.30.0/24",
            "172.16.10.0/24",
            "172.16.20.0/24",
            "192.168.100.0/24",
            "192.168.200.0/24",
        ]
        options = [c for c in candidates if c != real_cidr]
        return self._rng.choice(options)

    def _generate_mac(self, os_profile: str) -> str:
        """Generate a realistic MAC address for the given OS profile."""
        profile = OS_PROFILES.get(os_profile, OS_PROFILES["ubuntu_22"])
        prefix = self._rng.choice(profile["mac_prefix"])
        suffix = ":".join(f"{self._rng.randint(0, 255):02X}" for _ in range(3))
        return f"{prefix}:{suffix}"

    def _generate_hostname(self, service_type: str, index: int) -> str:
        """Generate a plausible hostname for a fake host."""
        name_templates = {
            "web_server": ["web", "www", "nginx", "apache", "frontend"],
            "database": ["db", "mysql", "postgres", "mongo", "data"],
            "file_server": ["files", "nas", "storage", "share", "backup"],
            "mail_server": ["mail", "smtp", "imap", "exchange", "mx"],
            "vpn_gateway": ["vpn", "gw", "tunnel", "remote"],
            "router": ["router", "core-sw", "dist-sw", "edge"],
            "workstation": ["ws", "desktop", "pc", "client", "host"],
        }
        base_names = name_templates.get(service_type, ["host"])
        name = self._rng.choice(base_names)
        domain_suffixes = ["corp.local", "internal", "lan", "home.arpa"]
        suffix = self._rng.choice(domain_suffixes)
        return f"{name}-{index:02d}.{suffix}"

    def _complexity_host_count(self) -> int:
        """Return number of fake hosts based on complexity setting."""
        ranges = {
            "low": (5, 15),
            "medium": (15, 30),
            "high": (30, min(self.max_hosts, 50)),
        }
        lo, hi = ranges[self.complexity]
        return self._rng.randint(lo, hi)

    def _adapt_to_ttp(self, ttp_class: str) -> list[str]:
        """
        Return service types that the AI engine prioritizes based on
        the attacker's known TTP class — making deception more convincing.
        """
        ttp_service_map = {
            "port_scanner": ["router", "web_server", "file_server", "workstation"],
            "web_attacker": ["web_server", "database", "mail_server"],
            "lateral_mover": ["workstation", "file_server", "database"],
            "recon_only": ["router", "vpn_gateway", "web_server"],
            "ransomware": ["file_server", "database", "workstation", "mail_server"],
            "apt": ["vpn_gateway", "router", "database", "file_server", "mail_server"],
            "unknown": list(SERVICES.keys()),
        }
        return ttp_service_map.get(ttp_class, ttp_service_map["unknown"])

    def _build_fake_host(
        self,
        ip: str,
        service_type: str,
        index: int,
        is_trap: bool = False
    ) -> FakeHost:
        """Construct a single FakeHost object with realistic attributes."""
        service_cfg = SERVICES[service_type]
        os_name = self._rng.choice(service_cfg["os"])
        os_profile = OS_PROFILES[os_name]

        # Combine OS default ports with service-specific ports
        open_ports = list(set(os_profile["open_ports"] + service_cfg["ports"]))

        # Build per-port banners
        banners = dict(os_profile.get("banners", {}))

        return FakeHost(
            ip=ip,
            mac=self._generate_mac(os_name),
            os_profile=os_name,
            services=[service_type],
            open_ports=sorted(open_ports),
            ttl=os_profile["ttl"],
            banners=banners,
            hostname=self._generate_hostname(service_type, index),
            is_trap=is_trap,
        )

    async def generate_for_attacker(
        self,
        attacker_profile: dict,
        morph_round: int = 0
    ) -> FakeTopology:
        """
        Generate a complete fake topology tailored to the given attacker profile.
        """
        attacker_ip = attacker_profile["source_ip"]
        ttp_class = attacker_profile.get("ttp_class", "unknown")

        self._seed_for_attacker(attacker_ip, morph_round)

        fake_subnet = self._pick_fake_subnet()
        subnet_net = ipaddress.ip_network(fake_subnet, strict=False)
        available_ips = list(subnet_net.hosts())

        # Reserve .1 as gateway
        gateway_ip = str(available_ips[0])
        host_ips = [str(ip) for ip in available_ips[1:]]

        preferred_services = self._adapt_to_ttp(ttp_class)
        host_count = self._complexity_host_count()

        topology = FakeTopology(
            attacker_ip=attacker_ip,
            subnet=fake_subnet,
            gateway_ip=gateway_ip,
            generation_id=hashlib.sha256(
                f"{attacker_ip}:{morph_round}".encode()
            ).hexdigest()[:12],
        )

        # Gateway (router)
        gateway_host = self._build_fake_host(gateway_ip, "router", 0)
        topology.hosts.append(gateway_host)

        # Regular fake hosts
        trap_indices = set(self._rng.sample(range(1, host_count), k=max(1, host_count // 8)))
        for i in range(1, host_count):
            ip = host_ips[i % len(host_ips)]
            service_type = preferred_services[i % len(preferred_services)]
            is_trap = (i in trap_indices) and self.config.get("forensic_traps_enabled", True)
            host = self._build_fake_host(ip, service_type, i, is_trap=is_trap)
            topology.hosts.append(host)

        self._attacker_topologies[attacker_ip] = topology
        self.logger.info(
            f"[TopologyGen] Generated topology for {attacker_ip}: "
            f"{len(topology.hosts)} hosts | TTP={ttp_class} | Round={morph_round}"
        )
        return topology

    async def morph_topology(
        self,
        current_attacker_ip: str,
        movement_event: dict
    ) -> FakeTopology:
        """
        Morph (regenerate) the topology for an attacker who has moved laterally.
        Uses a new morph_round seed so the topology changes completely.
        """
        current = self._attacker_topologies.get(current_attacker_ip)
        morph_round = 1
        if current:
            # Extract round from generation_id seed tracking
            morph_round = hash(current.generation_id) % 1000 + 1

        attacker_profile = {
            "source_ip": current_attacker_ip,
            "ttp_class": movement_event.get("ttp_class", "lateral_mover"),
        }
        new_topology = await self.generate_for_attacker(attacker_profile, morph_round)
        self.logger.info(
            f"[TopologyGen] Morphed topology for {current_attacker_ip} "
            f"(round {morph_round}) — attacker's map is now invalid."
        )
        return new_topology

    def get_topology_for(self, attacker_ip: str) -> Optional[FakeTopology]:
        return self._attacker_topologies.get(attacker_ip)
