"""
PHANTOMNET — Unit Tests: Topology Generator
"""

import asyncio
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.ai_engine.topology_generator import TopologyGenerator
from core.topology.graph_manager import GraphManager

CONFIG = {
    "log_level": "ERROR",
    "network_cidr": "192.168.1.0/24",
    "max_fake_hosts": 30,
    "topology_complexity": "medium",
    "forensic_traps_enabled": True,
}


async def test_generate_basic():
    gm = GraphManager(CONFIG)
    gen = TopologyGenerator(CONFIG, gm)
    profile = {"source_ip": "10.0.0.99", "ttp_class": "port_scanner", "confidence": 0.8}
    topo = await gen.generate_for_attacker(profile)
    assert topo.attacker_ip == "10.0.0.99"
    assert len(topo.hosts) > 0
    assert topo.gateway_ip != ""
    assert topo.generation_id != ""
    print(f"  [PASS] Basic generation: {len(topo.hosts)} hosts, subnet={topo.subnet}")


async def test_no_real_ip_overlap():
    gm = GraphManager(CONFIG)
    for i in range(1, 6):
        await gm.add_host(f"192.168.1.{i}", f"AA:BB:CC:DD:EE:{i:02X}")
    gen = TopologyGenerator(CONFIG, gm)
    profile = {"source_ip": "10.0.0.5", "ttp_class": "apt", "confidence": 0.9}
    topo = await gen.generate_for_attacker(profile)
    real_ips = set(gm.get_real_ips())
    for host in topo.hosts:
        assert host.ip not in real_ips, f"Fake host {host.ip} overlaps with real host!"
    print(f"  [PASS] No overlap with {len(real_ips)} real IPs")


async def test_morph_changes_topology():
    gm = GraphManager(CONFIG)
    gen = TopologyGenerator(CONFIG, gm)
    profile = {"source_ip": "10.0.0.7", "ttp_class": "lateral_mover", "confidence": 0.75}
    topo1 = await gen.generate_for_attacker(profile)
    movement = {
        "attacker_ip": "10.0.0.7",
        "source": "10.10.20.5",
        "destination": "10.10.20.6",
        "ttp_class": "lateral_mover"
    }
    topo2 = await gen.morph_topology("10.0.0.7", movement)
    assert topo1.generation_id != topo2.generation_id
    print(f"  [PASS] Morph changed topology: {topo1.generation_id} -> {topo2.generation_id}")


async def test_all_hosts_have_required_fields():
    gm = GraphManager(CONFIG)
    gen = TopologyGenerator(CONFIG, gm)
    profile = {"source_ip": "10.0.0.10", "ttp_class": "unknown", "confidence": 0.5}
    topo = await gen.generate_for_attacker(profile)
    for h in topo.hosts:
        assert h.ip
        assert h.mac
        assert h.os_profile
        assert isinstance(h.open_ports, list)
        assert h.ttl > 0
    print(f"  [PASS] All {len(topo.hosts)} hosts have required fields")


async def test_trap_hosts_present():
    gm = GraphManager(CONFIG)
    gen = TopologyGenerator(CONFIG, gm)
    profile = {"source_ip": "10.0.0.11", "ttp_class": "ransomware", "confidence": 0.85}
    topo = await gen.generate_for_attacker(profile)
    traps = [h for h in topo.hosts if h.is_trap]
    assert len(traps) > 0, "At least one trap host must be present"
    print(f"  [PASS] {len(traps)} trap hosts in topology")


async def test_to_dict_serializable():
    gm = GraphManager(CONFIG)
    gen = TopologyGenerator(CONFIG, gm)
    profile = {"source_ip": "10.0.0.12", "ttp_class": "recon_only", "confidence": 0.65}
    topo = await gen.generate_for_attacker(profile)
    import json
    d = topo.to_dict()
    json_str = json.dumps(d)
    assert len(json_str) > 0
    print(f"  [PASS] to_dict() is JSON-serializable ({len(json_str)} bytes)")


async def main():
    print("\n=== PHANTOMNET Topology Generator Tests ===")
    await test_generate_basic()
    await test_no_real_ip_overlap()
    await test_morph_changes_topology()
    await test_all_hosts_have_required_fields()
    await test_trap_hosts_present()
    await test_to_dict_serializable()
    print("\n[ALL TESTS PASSED]\n")


if __name__ == "__main__":
    asyncio.run(main())
