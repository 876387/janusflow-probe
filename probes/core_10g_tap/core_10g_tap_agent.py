#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JanusFlow (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com)
Core Network 10G/40G Optical TAP / Switch SPAN High-Throughput Probe Agent (`core_10g_tap_agent.py`).

Features:
  - Continuous verification (and optional enforcement) of `ethtool -k` NIC offload lockdown (`tso/gso/gro=off`).
  - Kernel AF_PACKET ring-buffered packet header capture (`snaplen=256`, 85%+ bandwidth reduction).
  - Automatic decapsulation of 802.1Q VLAN, 802.1ad QinQ, PPPoE, and VXLAN (UDP 4789) mirror frames.
  - Single-pass adaptive TCP MSS estimation (`est_mss`) & TSO/GSO/GRO super-frame folding (`FlowSketch v2 2.0-pa`).
  - Submits compact `.v2.fsk.jsonl.gz` sketches to JanusFlow Dual-Tower & PCDN endpoints over TLS 1.3 + HMAC-SHA256 v2.

Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent
# Resolve the `janusflow_probe` library from (1) a git checkout, (2) the router/server install
# prefix used by the bundled installers, or (3) a regular `pip install`.
for _cand in (HERE.parent.parent / "src", Path("/usr/lib/janusflow")):
    if (_cand / "janusflow_probe").is_dir() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))

from janusflow_probe.client import DEFAULT_PUBLIC_ENDPOINT, ClawNexusClient, load_credentials  # noqa: E402
from janusflow_probe.flowsketch import (  # noqa: E402
    FSK_SCHEMA_VERSION_V2_PA,
    build_synthetic_demo_pcap_bytes,
    convert_pcap_file_to_flowsketch_gz,
    parse_capture_bytes_to_flow_records,
    verify_ethtool_offloads_disabled,
)


def audit_and_lock_10g_nic(iface: str, enforce_offload_off: bool = True) -> Dict[str, Any]:
    ethtool_bin = shutil.which("ethtool")
    if not ethtool_bin:
        return {
            "offload_state": "ETHTOOL_MISSING",
            "compliant": False,
            "iface": iface,
        }
    if enforce_offload_off:
        subprocess.run(
            [ethtool_bin, "-K", iface, "tso", "off", "gso", "off", "gro", "off", "lro", "off"],
            capture_output=True,
            text=True,
        )
    res = subprocess.run([ethtool_bin, "-k", iface], capture_output=True, text=True)
    audit = verify_ethtool_offloads_disabled(res.stdout)
    audit["iface"] = iface
    return audit


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="janusflow-10g-tap-agent",
        description="JanusFlow Core Network 10G/40G Optical TAP / SPAN Mirror Probe Agent",
    )
    ap.add_argument("--endpoint", default=None, help=f"Gateway URL (default: {DEFAULT_PUBLIC_ENDPOINT})")
    ap.add_argument("--api-key", default=None, help="API Key (or env JANUSFLOW_API_KEY / CLAW_API_KEY)")
    ap.add_argument("--secret", default=None, help="HMAC Sign Secret (or env JANUSFLOW_SIGN_SECRET / CLAW_SIGN_SECRET)")
    ap.add_argument("--iface", default=os.environ.get("JANUSFLOW_IFACE", "eth1"), help="10G/40G mirror interface")
    ap.add_argument("--device-id", default=os.environ.get("JANUSFLOW_DEVICE_ID", "core-tap-10g-01"))
    ap.add_argument("--local-cidr", default=os.environ.get("JANUSFLOW_LOCAL_CIDR", "10.0.0.0/8,100.64.0.0/10"))
    ap.add_argument("--interval", type=int, default=int(os.environ.get("JANUSFLOW_INTERVAL", "30")))
    ap.add_argument("--snaplen", type=int, default=256)
    ap.add_argument("--ring-mb", type=int, default=int(os.environ.get("JANUSFLOW_RING_MB", "256")))
    ap.add_argument("--mode", choices=["both", "profile", "pcdn"], default=os.environ.get("JANUSFLOW_MODE", "both"))
    ap.add_argument("--enforce-offload-off", action="store_true", default=True)
    ap.add_argument("--work-dir", default="/var/run/janusflow_10g", help="In-memory working directory")
    ap.add_argument("--once", action="store_true", help="Run a single window and exit")
    ap.add_argument("--self-test", action="store_true", help="Run offline 10G TAP + TSO super-frame folding self-test")
    args = ap.parse_args()

    if args.self_test:
        demo_pcap = build_synthetic_demo_pcap_bytes(include_tso_superframe=True)
        recs = parse_capture_bytes_to_flow_records(demo_pcap, filename="core_10g_tap_selftest.pcap")
        eth_audit = verify_ethtool_offloads_disabled(
            "tcp-segmentation-offload: off\ngeneric-segmentation-offload: off\ngeneric-receive-offload: off\n"
        )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "agent": "janusflow-10g-tap-agent",
                    "fsk_version": FSK_SCHEMA_VERSION_V2_PA,
                    "flows_extracted": len(recs),
                    "sample_sni": recs[0].get("sni") if recs else None,
                    "est_mss": recs[0].get("est_mss") if recs else None,
                    "tso_superframes_folded": recs[0].get("oversized_up_pkts") if recs else 0,
                    "tso_equiv_wire_segs": recs[0].get("oversized_up_equiv_segs") if recs else 0,
                    "ethtool_validator_compliant": eth_audit["compliant"],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    creds = load_credentials(endpoint=args.endpoint, api_key=args.api_key, sign_secret=args.secret)
    client = ClawNexusClient(
        endpoint=creds["endpoint"],
        api_key=creds["api_key"],
        sign_secret=creds["sign_secret"],
        spki_pins=creds["spki_pins"],
        timeout=90.0,
    )

    tcpdump_bin = shutil.which("tcpdump")
    if not tcpdump_bin:
        print(json.dumps({"status": "error", "message": "tcpdump not installed"}), file=sys.stderr)
        return 1

    nic_audit = audit_and_lock_10g_nic(args.iface, enforce_offload_off=args.enforce_offload_off)
    print(json.dumps({"event": "10g_tap_startup_nic_audit", **nic_audit}, ensure_ascii=False), file=sys.stderr)

    work_dir = Path(args.work_dir)
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        work_dir = Path("/tmp/janusflow_10g")
        work_dir.mkdir(parents=True, exist_ok=True)

    ring_kb = max(4096, int(args.ring_mb) * 1024)
    cycle = 0
    while True:
        cycle += 1
        pcap_p = work_dir / f"tap10g_{os.getpid()}_{cycle}.pcap"
        fsk_p = work_dir / f"tap10g_{os.getpid()}_{cycle}.v2.fsk.jsonl.gz"
        try:
            cmd = [
                tcpdump_bin,
                "-i",
                args.iface,
                "-nn",
                "-U",
                "-B",
                str(ring_kb),
                "-s",
                str(max(128, int(args.snaplen))),
                "-G",
                str(max(5, int(args.interval))),
                "-W",
                "1",
                "-w",
                str(pcap_p),
                "ip",
                "or",
                "ip6",
                "or",
                "vlan",
            ]
            t0 = time.time()
            subprocess.run(cmd, capture_output=True, text=True)
            if not pcap_p.exists() or pcap_p.stat().st_size <= 24:
                if args.once:
                    return 0
                time.sleep(1.0)
                continue

            sketch_meta = convert_pcap_file_to_flowsketch_gz(pcap_p, output_path=fsk_p)
            pcap_p.unlink(missing_ok=True)

            fields: Dict[str, str] = {"device_id": args.device_id}
            if args.local_cidr.strip():
                fields["local_cidr"] = args.local_cidr.strip()

            out_log: Dict[str, Any] = {
                "ts": int(time.time()),
                "cycle": cycle,
                "device_id": args.device_id,
                "iface": args.iface,
                "window_sec": round(time.time() - t0, 2),
                "nic_offload_state": nic_audit.get("offload_state"),
                "sketch_meta": sketch_meta,
            }
            if args.mode in ("both", "profile"):
                st_p, res_p = client.upload_multipart("/api/v2/traffic/profile-period", file_path=fsk_p, fields=fields)
                out_log["profile_status"] = st_p
                out_log["profile"] = res_p
            if args.mode in ("both", "pcdn"):
                st_c, res_c = client.upload_multipart("/api/v2/traffic/pcdn-scan", file_path=fsk_p, fields=fields)
                out_log["pcdn_status"] = st_c
                out_log["pcdn"] = res_c

            print(json.dumps(out_log, ensure_ascii=False))
        finally:
            pcap_p.unlink(missing_ok=True)
            fsk_p.unlink(missing_ok=True)

        if args.once:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
