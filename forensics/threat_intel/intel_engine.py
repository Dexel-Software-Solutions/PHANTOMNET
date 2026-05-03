"""
PHANTOMNET — Threat Intelligence Engine
Records attacker events and generates structured threat intel reports.
"""

import asyncio
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from utils.logger import setup_logger


@dataclass
class ThreatRecord:
    attacker_ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ttp_class: str = "unknown"
    confidence: float = 0.0
    movements: list = field(default_factory=list)
    traps_triggered: list = field(default_factory=list)
    topology_morphs: int = 0

    def to_dict(self) -> dict:
        return {
            "attacker_ip": self.attacker_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "ttp_class": self.ttp_class,
            "confidence": round(self.confidence, 3),
            "movements": self.movements,
            "traps_triggered": self.traps_triggered,
            "topology_morphs": self.topology_morphs,
            "threat_score": self._compute_threat_score(),
        }

    def _compute_threat_score(self) -> int:
        """Compute 0–100 threat score from attacker behavior."""
        score = 0
        ttp_scores = {
            "apt": 90, "ransomware": 85, "lateral_mover": 75,
            "web_attacker": 60, "port_scanner": 40, "recon_only": 25, "unknown": 10,
        }
        score += ttp_scores.get(self.ttp_class, 10)
        score += min(len(self.movements) * 5, 30)
        score += min(len(self.traps_triggered) * 10, 30)
        return min(score, 100)


class ThreatIntelEngine:
    """
    Records all attacker events and writes structured threat intel
    to a JSON file for export or SIEM integration.
    """

    def __init__(self, config: dict):
        self.config = config
        self.logger = setup_logger("ThreatIntel", config.get("log_level", "INFO"))
        self._records: dict[str, ThreatRecord] = {}
        self._output_path = Path(config.get("threat_intel_output", "logs/threat_intel.json"))
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None

    async def start(self):
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._flush_task = asyncio.create_task(self._periodic_flush())
        self.logger.info(f"[ThreatIntel] Started. Output: {self._output_path}")

    async def record_attacker(self, profile: dict):
        async with self._lock:
            ip = profile["source_ip"]
            if ip not in self._records:
                self._records[ip] = ThreatRecord(attacker_ip=ip)
            rec = self._records[ip]
            rec.last_seen = time.time()
            rec.ttp_class = profile.get("ttp_class", "unknown")
            rec.confidence = profile.get("confidence", 0.0)

    async def record_movement(self, event: dict):
        async with self._lock:
            ip = event.get("attacker_ip", "")
            if ip not in self._records:
                self._records[ip] = ThreatRecord(attacker_ip=ip)
            rec = self._records[ip]
            rec.last_seen = time.time()
            rec.movements.append({
                "from": event.get("source"),
                "to": event.get("destination"),
                "port": event.get("port"),
                "timestamp": event.get("timestamp"),
            })
            rec.topology_morphs += 1

    async def record_trap_trigger(self, event: dict):
        async with self._lock:
            ip = event.get("attacker_ip", "")
            if ip not in self._records:
                self._records[ip] = ThreatRecord(attacker_ip=ip)
            self._records[ip].traps_triggered.append(event)
            self._records[ip].last_seen = time.time()

    def get_all_records(self) -> list[dict]:
        return [r.to_dict() for r in self._records.values()]

    def get_record(self, ip: str) -> Optional[dict]:
        rec = self._records.get(ip)
        return rec.to_dict() if rec else None

    async def _periodic_flush(self):
        """Write threat intel to disk every 30 seconds."""
        while True:
            await asyncio.sleep(30)
            await self._flush()

    async def _flush(self):
        async with self._lock:
            data = {
                "generated_at": time.time(),
                "total_attackers": len(self._records),
                "records": [r.to_dict() for r in self._records.values()],
            }
        try:
            with open(self._output_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            self.logger.error(f"[ThreatIntel] Flush failed: {e}")

    async def stop(self):
        if self._flush_task:
            self._flush_task.cancel()
        await self._flush()
        self.logger.info("[ThreatIntel] Final flush complete. Stopped.")
