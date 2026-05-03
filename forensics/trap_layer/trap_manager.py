"""
PHANTOMNET — Forensic Trap Manager
Deploys interactive honeypot services on fake host IPs.
Captures attacker credentials, commands, and behavior.
"""

import asyncio
import time
import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional

from utils.logger import setup_logger
from core.ai_engine.topology_generator import FakeTopology


@dataclass
class TrapEvent:
    trap_id: str
    attacker_ip: str
    attacker_port: int
    trap_type: str
    trap_ip: str
    trap_port: int
    timestamp: float
    captured_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "trap_id": self.trap_id,
            "attacker_ip": self.attacker_ip,
            "attacker_port": self.attacker_port,
            "trap_type": self.trap_type,
            "trap_ip": self.trap_ip,
            "trap_port": self.trap_port,
            "timestamp": self.timestamp,
            "captured_data": self.captured_data,
        }


class SSHHoneypot:
    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def __init__(self, host: str, port: int, trap_id: str, on_capture: Callable):
        self.host = host
        self.port = port
        self.trap_id = trap_id
        self.on_capture = on_capture
        self._server: Optional[asyncio.Server] = None

    async def start(self):
        try:
            self._server = await asyncio.start_server(
                self._handle, self.host, self.port
            )
        except OSError:
            pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername", ("0.0.0.0", 0))
        attacker_ip, attacker_port = peer[0], peer[1]
        try:
            writer.write(self.BANNER)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            event = TrapEvent(
                trap_id=self.trap_id,
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                trap_type="ssh",
                trap_ip=self.host,
                trap_port=self.port,
                timestamp=time.time(),
                captured_data={
                    "client_banner": raw[:80].decode("utf-8", errors="replace").strip(),
                    "bytes_received": len(raw),
                },
            )
            await self.on_capture(event)
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            writer.close()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class HTTPHoneypot:
    FAKE_RESPONSE = (
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\nContent-Length: 45\r\n\r\n"
        b"<html><body>Internal Server</body></html>\r\n"
    )

    def __init__(self, host: str, port: int, trap_id: str, on_capture: Callable):
        self.host = host
        self.port = port
        self.trap_id = trap_id
        self.on_capture = on_capture
        self._server: Optional[asyncio.Server] = None

    async def start(self):
        try:
            self._server = await asyncio.start_server(
                self._handle, self.host, self.port
            )
        except OSError:
            pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername", ("0.0.0.0", 0))
        attacker_ip, attacker_port = peer[0], peer[1]
        try:
            raw = await asyncio.wait_for(reader.read(8192), timeout=10.0)
            request_text = raw.decode("utf-8", errors="replace")
            lines = request_text.splitlines()
            writer.write(self.FAKE_RESPONSE)
            await writer.drain()
            event = TrapEvent(
                trap_id=self.trap_id,
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                trap_type="http",
                trap_ip=self.host,
                trap_port=self.port,
                timestamp=time.time(),
                captured_data={
                    "request_line": lines[0] if lines else "",
                    "user_agent": next(
                        (l for l in lines if l.lower().startswith("user-agent:")), ""
                    ),
                    "bytes_received": len(raw),
                },
            )
            await self.on_capture(event)
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            writer.close()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class TrapManager:
    TRAP_PORT_MAP = {22: SSHHoneypot, 80: HTTPHoneypot}

    def __init__(self, config: dict):
        self.config = config
        self.logger = setup_logger("TrapManager", config.get("log_level", "INFO"))
        self._active_traps: list = []
        self._running = False
        self.on_trap_triggered: Optional[Callable] = None

    async def start(self):
        self._running = True
        self.logger.info("[TrapManager] Started.")

    async def deploy_traps(self, topology: FakeTopology):
        if not self.config.get("forensic_traps_enabled", True):
            return
        for host in topology.hosts:
            if not host.is_trap:
                continue
            for port in host.open_ports:
                if port not in self.TRAP_PORT_MAP:
                    continue
                trap_id = hashlib.sha256(
                    f"{host.ip}:{port}:{topology.generation_id}".encode()
                ).hexdigest()[:12]
                TrapClass = self.TRAP_PORT_MAP[port]
                trap = TrapClass(host.ip, port, trap_id, self._on_capture)
                try:
                    await trap.start()
                    self._active_traps.append(trap)
                    self.logger.info(
                        f"[TrapManager] {TrapClass.__name__} trap deployed "
                        f"on {host.ip}:{port} id={trap_id}"
                    )
                except Exception as e:
                    self.logger.debug(f"[TrapManager] Deploy failed {host.ip}:{port}: {e}")

    async def _on_capture(self, event: TrapEvent):
        self.logger.critical(
            f"[TRAP TRIGGERED] {event.trap_type.upper()} | "
            f"Attacker: {event.attacker_ip} | Trap: {event.trap_ip}:{event.trap_port}"
        )
        if self.on_trap_triggered:
            await self.on_trap_triggered(event.to_dict())

    async def stop(self):
        self._running = False
        for trap in self._active_traps:
            await trap.stop()
        self.logger.info(f"[TrapManager] Stopped {len(self._active_traps)} traps.")
