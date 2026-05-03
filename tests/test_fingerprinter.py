"""
PHANTOMNET — Unit Tests: Attacker Behavioral Fingerprinter
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.behavioral.fingerprinter import AttackerFingerprinter

CONFIG = {"log_level": "ERROR"}


async def _async_noop(*args, **kwargs):
    pass


async def make_packet(src_ip, dst_ip, dst_port, protocol="TCP", flags=None):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 54321, "dst_port": dst_port,
        "protocol": protocol, "flags": flags or [],
    }


async def test_port_scanner_classification():
    fp = AttackerFingerprinter(CONFIG)
    fp.on_attacker_detected = _async_noop
    for port in range(20, 200):
        pkt = await make_packet("10.0.0.1", "192.168.1.5", port, flags=["SYN"])
        await fp.analyze_packet(pkt)
    profile = fp.get_profile("10.0.0.1")
    assert profile is not None
    assert profile.syn_count > 0
    print(f"  [PASS] port_scanner: ttp={profile.ttp_class} conf={profile.confidence:.2f}")


async def test_smb_lateral_mover():
    fp = AttackerFingerprinter(CONFIG)
    fp.on_lateral_movement = _async_noop
    for host_octet in range(1, 20):
        for _ in range(3):
            pkt = await make_packet("10.0.0.2", f"192.168.1.{host_octet}", 445, flags=["SYN"])
            await fp.analyze_packet(pkt)
    profile = fp.get_profile("10.0.0.2")
    assert profile is not None
    assert profile.smb_attempts > 0
    print(f"  [PASS] lateral_mover: ttp={profile.ttp_class} smb={profile.smb_attempts}")


async def test_loopback_ignored():
    fp = AttackerFingerprinter(CONFIG)
    for _ in range(50):
        pkt = await make_packet("127.0.0.1", "127.0.0.1", 80)
        await fp.analyze_packet(pkt)
    assert fp.get_profile("127.0.0.1") is None
    print("  [PASS] loopback packets correctly ignored")


async def test_web_attacker():
    fp = AttackerFingerprinter(CONFIG)
    fp.on_attacker_detected = _async_noop
    for _ in range(60):
        for port in [80, 443, 8080]:
            pkt = await make_packet("10.0.0.3", "192.168.1.10", port, flags=["SYN", "ACK"])
            await fp.analyze_packet(pkt)
    profile = fp.get_profile("10.0.0.3")
    assert profile is not None
    assert profile.http_requests > 0
    print(f"  [PASS] web_attacker: ttp={profile.ttp_class} http_reqs={profile.http_requests}")


async def test_all_profiles_serializable():
    fp = AttackerFingerprinter(CONFIG)
    fp.on_attacker_detected = _async_noop
    for i in range(20):
        pkt = await make_packet(f"10.0.{i}.1", "192.168.1.1", 22, flags=["SYN"])
        await fp.analyze_packet(pkt)
    profiles = fp.all_profiles()
    assert isinstance(profiles, list)
    for p in profiles:
        assert "source_ip" in p
        assert "ttp_class" in p
        assert "confidence" in p
    print(f"  [PASS] all_profiles(): {len(profiles)} dicts returned")


async def main():
    print("\n=== PHANTOMNET Fingerprinter Tests ===")
    await test_loopback_ignored()
    await test_port_scanner_classification()
    await test_smb_lateral_mover()
    await test_web_attacker()
    await test_all_profiles_serializable()
    print("\n[ALL TESTS PASSED]\n")


if __name__ == "__main__":
    asyncio.run(main())
