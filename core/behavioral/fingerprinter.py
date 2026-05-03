"""
PHANTOMNET — Attacker Behavioral Fingerprinter
Analyzes packet patterns to classify attacker TTPs in real-time.
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from utils.logger import setup_logger


TTP_SIGNATURES = {
    "port_scanner": {
        "description": "Sequential or random port scanning behavior",
        "indicators": {
            "unique_ports_per_minute": 20,
            "syn_without_ack_ratio": 0.8,
        },
    },
    "web_attacker": {
        "description": "HTTP/HTTPS targeted attack patterns",
        "indicators": {
            "target_ports": [80, 443, 8080, 8443],
            "high_request_rate": 50,
        },
    },
    "lateral_mover": {
        "description": "Internal network lateral movement",
        "indicators": {
            "target_ports": [445, 139, 3389, 22],
        },
    },
    "recon_only": {
        "description": "Passive reconnaissance — low and slow",
        "indicators": {
            "unique_ports_per_minute": 3,
        },
    },
    "ransomware": {
        "description": "Ransomware propagation behavior",
        "indicators": {
            "target_ports": [445, 3389, 22],
            "smb_brute": True,
        },
    },
    "apt": {
        "description": "Advanced Persistent Threat — slow, targeted, multi-vector",
        "indicators": {
            "unique_ports_per_minute": 2,
            "long_session_duration": True,
        },
    },
}


@dataclass
class AttackerProfile:
    source_ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ttp_class: str = "unknown"
    confidence: float = 0.0
    packet_count: int = 0
    unique_ports: set = field(default_factory=set)
    target_ips: set = field(default_factory=set)
    syn_count: int = 0
    ack_count: int = 0
    icmp_count: int = 0
    smb_attempts: int = 0
    http_requests: int = 0
    port_access_times: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_ip": self.source_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "ttp_class": self.ttp_class,
            "confidence": round(self.confidence, 3),
            "packet_count": self.packet_count,
            "unique_ports_seen": len(self.unique_ports),
            "unique_targets": len(self.target_ips),
            "syn_count": self.syn_count,
            "icmp_count": self.icmp_count,
            "smb_attempts": self.smb_attempts,
        }


class AttackerFingerprinter:
    """
    Real-time attacker fingerprinter.
    Classifies attacker TTPs from live packet metadata.
    """

    DETECTION_THRESHOLD = 15
    LATERAL_MOVEMENT_PORTS = {445, 139, 3389, 22, 5985}
    SCAN_RATE_THRESHOLD = 15
    CONFIDENCE_THRESHOLD = 0.60

    def __init__(self, config: dict):
        self.config = config
        self.logger = setup_logger("Fingerprinter", config.get("log_level", "INFO"))
        self._profiles: dict[str, AttackerProfile] = {}
        self._lock = asyncio.Lock()
        self._alerted: set[str] = set()

        self.on_attacker_detected: Optional[Callable] = None
        self.on_lateral_movement: Optional[Callable] = None

    async def analyze_packet(self, packet_meta: dict):
        src_ip = packet_meta.get("src_ip", "")
        dst_ip = packet_meta.get("dst_ip", "")
        dst_port = packet_meta.get("dst_port", 0)
        protocol = packet_meta.get("protocol", "")
        flags = packet_meta.get("flags", [])

        if not src_ip or src_ip.startswith("127.") or src_ip.startswith("::1"):
            return

        async with self._lock:
            if src_ip not in self._profiles:
                self._profiles[src_ip] = AttackerProfile(source_ip=src_ip)

            profile = self._profiles[src_ip]
            profile.packet_count += 1
            profile.last_seen = time.time()

            if dst_ip:
                profile.target_ips.add(dst_ip)
            if dst_port:
                profile.unique_ports.add(dst_port)
                profile.port_access_times.append((time.time(), dst_port))

            if "SYN" in flags and "ACK" not in flags:
                profile.syn_count += 1
            if "ACK" in flags:
                profile.ack_count += 1

            if protocol == "ICMP":
                profile.icmp_count += 1
            if dst_port in (445, 139):
                profile.smb_attempts += 1
            if dst_port in (80, 443, 8080, 8443):
                profile.http_requests += 1

            if dst_port in self.LATERAL_MOVEMENT_PORTS and len(profile.target_ips) > 2:
                await self._check_lateral_movement(profile, packet_meta)

            if profile.packet_count >= self.DETECTION_THRESHOLD:
                await self._classify_and_alert(profile)

    async def _classify_and_alert(self, profile: AttackerProfile):
        ttp_class, confidence = self._classify_ttp(profile)
        profile.ttp_class = ttp_class
        profile.confidence = confidence

        if (
            confidence >= self.CONFIDENCE_THRESHOLD
            and profile.source_ip not in self._alerted
            and self.on_attacker_detected
        ):
            self._alerted.add(profile.source_ip)
            self.logger.warning(
                f"[Fingerprinter] Attacker classified: {profile.source_ip} "
                f"-> {ttp_class} (confidence={confidence:.2f})"
            )
            asyncio.create_task(self.on_attacker_detected(profile.to_dict()))

    async def _check_lateral_movement(self, profile: AttackerProfile, packet_meta: dict):
        if self.on_lateral_movement:
            event = {
                "attacker_ip": profile.source_ip,
                "source": packet_meta.get("src_ip"),
                "destination": packet_meta.get("dst_ip"),
                "port": packet_meta.get("dst_port"),
                "ttp_class": profile.ttp_class,
                "timestamp": time.time(),
            }
            asyncio.create_task(self.on_lateral_movement(event))

    def _classify_ttp(self, profile: AttackerProfile) -> tuple[str, float]:
        scores: dict[str, float] = {}

        elapsed = max(profile.last_seen - profile.first_seen, 1.0)
        ports_per_minute = (len(profile.unique_ports) / elapsed) * 60
        total_tcp = profile.syn_count + profile.ack_count
        syn_ratio = profile.syn_count / max(total_tcp, 1)

        score = 0.0
        if ports_per_minute >= self.SCAN_RATE_THRESHOLD:
            score += 0.5
        if syn_ratio >= 0.8:
            score += 0.3
        if len(profile.unique_ports) > 100:
            score += 0.2
        scores["port_scanner"] = min(score, 1.0)

        score = 0.0
        web_ports = {80, 443, 8080, 8443}
        if len(profile.unique_ports & web_ports) >= 2:
            score += 0.4
        if profile.http_requests > 20:
            score += 0.4
        if len(profile.target_ips) <= 3:
            score += 0.2
        scores["web_attacker"] = min(score, 1.0)

        score = 0.0
        lateral_ports = {445, 139, 3389, 22, 5985}
        if len(profile.unique_ports & lateral_ports) >= 2:
            score += 0.5
        if len(profile.target_ips) > 3:
            score += 0.3
        if profile.smb_attempts > 5:
            score += 0.2
        scores["lateral_mover"] = min(score, 1.0)

        score = 0.0
        if ports_per_minute < 3:
            score += 0.4
        if profile.icmp_count > 10:
            score += 0.3
        if len(profile.target_ips) > 5 and profile.packet_count < 50:
            score += 0.3
        scores["recon_only"] = min(score, 1.0)

        score = 0.0
        if profile.smb_attempts > 20:
            score += 0.5
        if len(profile.target_ips) > 10:
            score += 0.3
        if ports_per_minute > 10:
            score += 0.2
        scores["ransomware"] = min(score, 1.0)

        score = 0.0
        if ports_per_minute < 2:
            score += 0.4
        if len(profile.target_ips) <= 5 and profile.packet_count > 100:
            score += 0.3
        if elapsed > 300:
            score += 0.3
        scores["apt"] = min(score, 1.0)

        best_ttp = max(scores, key=lambda k: scores[k])
        best_score = scores[best_ttp]

        if best_score < 0.3:
            return "unknown", best_score

        return best_ttp, best_score

    def get_profile(self, ip: str) -> Optional[AttackerProfile]:
        return self._profiles.get(ip)

    def all_profiles(self) -> list[dict]:
        return [p.to_dict() for p in self._profiles.values()]
