"""
PHANTOMNET — Packet Interceptor
Linux: launches Go binary via subprocess (real capture)
Fallback: Python simulation mode
"""

import asyncio
import json
import platform
import random
from pathlib import Path
from typing import Callable, Optional

from utils.logger import setup_logger

IS_LINUX = platform.system() == "Linux"


class PacketInterceptor:
    GO_BINARY = Path(__file__).parent / "bin" / "pktengine"

    def __init__(self, config: dict):
        self.config = config
        self.logger = setup_logger("PacketInterceptor", config.get("log_level", "INFO"))
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False
        self.on_packet: Optional[Callable] = None

    async def start(self, interface: str):
        self._running = True
        if IS_LINUX and self.GO_BINARY.exists():
            self.logger.info(f"[PacketInterceptor] Starting Go engine on {interface}")
            await self._go_mode(interface)
        else:
            if IS_LINUX:
                self.logger.warning(
                    "[PacketInterceptor] Go binary not found. "
                    "Run 'make build-go' to compile. Using simulation mode."
                )
            else:
                self.logger.info("[PacketInterceptor] Non-Linux platform — simulation mode.")
            await self._simulation_mode(interface)

    async def _go_mode(self, interface: str):
        self._process = await asyncio.create_subprocess_exec(
            str(self.GO_BINARY),
            "--interface", interface,
            "--format", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.gather(self._read_packets(), self._log_stderr())

    async def _read_packets(self):
        while self._running and self._process:
            try:
                line = await asyncio.wait_for(self._process.stdout.readline(), timeout=5.0)
                if not line:
                    break
                meta = json.loads(line.decode().strip())
                if self.on_packet:
                    await self.on_packet(meta)
            except asyncio.TimeoutError:
                continue
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            except asyncio.CancelledError:
                break

    async def _log_stderr(self):
        while self._running and self._process:
            try:
                line = await asyncio.wait_for(self._process.stderr.readline(), timeout=5.0)
                if line:
                    self.logger.debug(f"[pktengine] {line.decode().strip()}")
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def _simulation_mode(self, interface: str):
        """Synthetic packet generator for testing without live capture."""
        self.logger.info("[PacketInterceptor] Simulation mode active.")
        sim_ips   = ["192.168.1.50", "10.0.0.99", "172.16.0.200", "10.10.10.5"]
        sim_ports = [22, 80, 443, 445, 3389, 8080, 135, 139, 23, 21, 3306, 5432]
        protocols = ["TCP", "UDP", "ICMP"]
        flag_sets = [["SYN"], ["SYN", "ACK"], ["ACK"], ["RST"], []]

        while self._running:
            src_ip = random.choice(sim_ips)
            pkt = {
                "src_ip":   src_ip,
                "dst_ip":   f"192.168.1.{random.randint(1, 50)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice(sim_ports),
                "protocol": random.choice(protocols),
                "flags":    random.choice(flag_sets),
                "length":   random.randint(40, 1500),
            }
            if self.on_packet:
                await self.on_packet(pkt)
            await asyncio.sleep(random.uniform(0.05, 0.3))

    async def stop(self):
        self._running = False
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
        self.logger.info("[PacketInterceptor] Stopped.")
