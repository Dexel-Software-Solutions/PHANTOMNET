"""
PHANTOMNET — Dashboard REST API
Provides real-time data to the frontend over HTTPS.
"""

import asyncio
import json
import ssl
import time
from pathlib import Path
from typing import Optional

from utils.logger import setup_logger


class DashboardAPI:
    """
    Minimal async HTTPS API server for the PHANTOMNET dashboard.
    No external framework dependencies — pure asyncio.
    """

    def __init__(self, config: dict, graph_manager, intel_engine):
        self.config = config
        self.graph_manager = graph_manager
        self.intel_engine = intel_engine
        self.logger = setup_logger("DashboardAPI", config.get("log_level", "INFO"))
        self.port = config.get("dashboard_port", 8443)
        self._server: Optional[asyncio.Server] = None

    async def start(self):
        ssl_ctx = self._build_ssl_context()
        self._server = await asyncio.start_server(
            self._handle_request, "0.0.0.0", self.port, ssl=ssl_ctx
        )
        self.logger.info(f"[DashboardAPI] Listening on https://0.0.0.0:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        cert = Path(self.config.get("dashboard_tls_cert", "config/certs/server.crt"))
        key = Path(self.config.get("dashboard_tls_key", "config/certs/server.key"))
        if cert.exists() and key.exists():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            return ctx
        self.logger.warning(
            "[DashboardAPI] TLS cert/key not found — running without TLS (dev mode)."
        )
        return None

    async def _handle_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            request = raw.decode("utf-8", errors="replace")
            first_line = request.splitlines()[0] if request else ""
            parts = first_line.split()
            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            if method == "GET":
                body, status = self._route_get(path)
            else:
                body, status = json.dumps({"error": "Method not allowed"}), 405

            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
            writer.write(response.encode())
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, IndexError):
            pass
        finally:
            writer.close()

    def _route_get(self, path: str) -> tuple[str, str]:
        routes = {
            "/api/status": self._status,
            "/api/topology": self._topology,
            "/api/attackers": self._attackers,
            "/api/threats": self._threats,
        }
        handler = routes.get(path)
        if handler:
            return json.dumps(handler(), indent=2), "200 OK"
        return json.dumps({"error": "Not found"}), "404 Not Found"

    def _status(self) -> dict:
        return {
            "status": "active",
            "timestamp": time.time(),
            "real_hosts": self.graph_manager.real_node_count(),
        }

    def _topology(self) -> dict:
        return self.graph_manager.to_dict()

    def _attackers(self) -> dict:
        return {"attackers": []}

    def _threats(self) -> dict:
        return {
            "records": self.intel_engine.get_all_records(),
            "total": len(self.intel_engine.get_all_records()),
        }

    async def stop(self):
        if self._server:
            self._server.close()
        self.logger.info("[DashboardAPI] Stopped.")
