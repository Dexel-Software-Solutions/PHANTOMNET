#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         PHANTOMNET — Autonomous Deceptive Network               ║
║              Topology Morphing Framework                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Author    : Demiyan Dissanayake                                 ║
║  Company   : Dexel Software Solutions                            ║
║  Location  : Dankotuwa, Sri Lanka                                ║
║  Email     : dexelsoftwaresolutions@gmail.com                    ║
║  GitHub    : github.com/Dexel-Software-Solutions                 ║
║  WhatsApp  : +94 72 950 4289                                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Platform  : Kali Linux / Ubuntu / Debian / ParrotOS / Arch     ║
║  License   : MIT | Version : 1.3                                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import signal
import asyncio
import platform
import argparse
from pathlib import Path


def _check_privileges():
    if platform.system() == "Linux":
        if os.geteuid() != 0:
            print("[PHANTOMNET] ERROR: Root privileges required.")
            print("             Run: sudo python3 phantomnet.py --config config/phantomnet.yaml")
            sys.exit(1)
    elif platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[PHANTOMNET] WARNING: Not running as Administrator.")
            print("             Some features may not work. Re-run PowerShell as Admin.")

_check_privileges()

from core.ai_engine.topology_generator import TopologyGenerator
from core.topology.graph_manager import GraphManager
from core.behavioral.fingerprinter import AttackerFingerprinter
from network.packet_engine.interceptor import PacketInterceptor
from network.protocol_deception.spoofer import ProtocolSpoofer
from forensics.trap_layer.trap_manager import TrapManager
from forensics.threat_intel.intel_engine import ThreatIntelEngine
from dashboard.api.server import DashboardAPI
from config.loader import ConfigLoader
from utils.logger import setup_logger


class PhantomNet:
    def __init__(self, config_path: str):
        self.config = ConfigLoader(config_path).load()
        self.logger = setup_logger("PHANTOMNET", self.config.get("log_level", "INFO"))
        self.running = False

        self.graph_manager      = GraphManager(self.config)
        self.topology_generator = TopologyGenerator(self.config, self.graph_manager)
        self.fingerprinter      = AttackerFingerprinter(self.config)
        self.packet_interceptor = PacketInterceptor(self.config)
        self.spoofer            = ProtocolSpoofer(self.config)
        self.trap_manager       = TrapManager(self.config)
        self.intel_engine       = ThreatIntelEngine(self.config)
        self.dashboard          = DashboardAPI(self.config, self.graph_manager, self.intel_engine)

        self._setup_callbacks()

    def _setup_callbacks(self):
        self.fingerprinter.on_attacker_detected = self._on_attacker_detected
        self.fingerprinter.on_lateral_movement  = self._on_lateral_movement
        self.trap_manager.on_trap_triggered     = self._on_trap_triggered
        self.packet_interceptor.on_packet       = self.fingerprinter.analyze_packet

    async def _on_attacker_detected(self, attacker_profile: dict):
        self.logger.warning(
            f"[!] Attacker detected: {attacker_profile['source_ip']} "
            f"| TTP: {attacker_profile['ttp_class']} "
            f"| Confidence: {attacker_profile['confidence']:.2f}"
        )
        fake_topology = await self.topology_generator.generate_for_attacker(attacker_profile)
        await self.spoofer.apply_topology(fake_topology, attacker_profile["source_ip"])
        await self.trap_manager.deploy_traps(fake_topology)
        await self.intel_engine.record_attacker(attacker_profile)

    async def _on_lateral_movement(self, movement_event: dict):
        self.logger.warning(
            f"[!] Lateral movement: "
            f"{movement_event['source']} -> {movement_event['destination']}"
        )
        new_topology = await self.topology_generator.morph_topology(
            current_attacker_ip=movement_event["attacker_ip"],
            movement_event=movement_event
        )
        await self.spoofer.apply_topology(new_topology, movement_event["attacker_ip"])
        await self.intel_engine.record_movement(movement_event)

    async def _on_trap_triggered(self, trap_event: dict):
        self.logger.critical(
            f"[TRAP] {trap_event['trap_id']} | Attacker: {trap_event['attacker_ip']}"
        )
        await self.intel_engine.record_trap_trigger(trap_event)

    async def start(self):
        self.running = True
        self.logger.info("=" * 66)
        self.logger.info("  PHANTOMNET — Deceptive Topology Morphing Framework v1.3")
        self.logger.info("  Author   : Demiyan Dissanayake")
        self.logger.info("  Company  : Dexel Software Solutions | Sri Lanka")
        self.logger.info("  Email    : dexelsoftwaresolutions@gmail.com")
        self.logger.info("  GitHub   : github.com/Dexel-Software-Solutions")
        self.logger.info("=" * 66)

        iface = self.config.get("interface", "eth0")
        self.logger.info(f"[*] Platform  : {platform.system()} {platform.release()}")
        self.logger.info(f"[*] Interface : {iface}")

        await self.graph_manager.discover_real_topology()
        self.logger.info(f"[*] Real hosts: {self.graph_manager.real_node_count()}")

        tasks = [
            self.packet_interceptor.start(iface),
            self.spoofer.start(),
            self.trap_manager.start(),
            self.intel_engine.start(),
            self.dashboard.start(),
        ]

        port = self.config.get("dashboard_port", 8443)
        self.logger.info(f"[*] Dashboard : https://localhost:{port}")
        self.logger.info("[*] PHANTOMNET is ACTIVE — Network deception engaged.")

        await asyncio.gather(*tasks)

    async def stop(self):
        self.running = False
        self.logger.info("[*] Shutting down PHANTOMNET...")
        await self.packet_interceptor.stop()
        await self.spoofer.stop()
        await self.trap_manager.stop()
        await self.intel_engine.stop()
        await self.dashboard.stop()
        self.logger.info("[*] PHANTOMNET stopped cleanly.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="PHANTOMNET — Autonomous Deceptive Network Topology Morphing Framework\n"
                    "Author: Demiyan Dissanayake | Dexel Software Solutions"
    )
    parser.add_argument("--config", "-c", default="config/phantomnet.yaml")
    parser.add_argument("--log-level", "-l",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    return parser.parse_args()


async def main():
    args = parse_args()
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[ERROR] Config not found: {config_path}")
        print("        cp config/phantomnet.yaml.example config/phantomnet.yaml")
        sys.exit(1)

    pnet = PhantomNet(str(config_path))
    loop = asyncio.get_running_loop()

    def _signal_handler():
        asyncio.create_task(pnet.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    await pnet.start()


if __name__ == "__main__":
    asyncio.run(main())
