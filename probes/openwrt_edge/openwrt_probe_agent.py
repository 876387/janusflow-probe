#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JanusFlow (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com)
Standalone Edge OpenWrt / Linux Gateway FlowSketch v2 Probe Agent (`openwrt_probe_agent.py`).

Features:
  - Runs on stock OpenWrt (`python3-light` + `python3-openssl` + `tcpdump-mini`) with zero third-party pip packages.
  - Captures packet headers only (`snaplen=256`) into `/var/run/janusflow` RAM directory (zero flash wear).
  - Optionally snapshots `/proc/net/nf_conntrack` byte counters to enrich long-lived elephant flows.
  - Compresses raw captures by 50x~150x locally into `.v2.fsk.jsonl.gz` FlowSketch v2 (`2.0-pa`) before
    transmitting over TLS 1.3 + HMAC-SHA256 v2 to the JanusFlow Dual-Tower Gateway.

Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
# Resolve the `janusflow_probe` library from (1) a git checkout, (2) the router/server install
# prefix used by the bundled installers, or (3) a regular `pip install`.
for _cand in (HERE.parent.parent / "src", Path("/usr/lib/janusflow")):
    if (_cand / "janusflow_probe").is_dir() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))

from janusflow_probe.client import DEFAULT_PUBLIC_ENDPOINT, ClawNexusClient, load_credentials  # noqa: E402
from janusflow_probe.flowsketch import (  # noqa: E402
    build_synthetic_demo_pcap_bytes,
    convert_pcap_file_to_flowsketch_gz,
    parse_capture_bytes_to_flow_records,
)

CONNTRACK_PROC_PATH = Path("/proc/net/nf_conntrack")


def snapshot_openwrt_conntrack(max_entries: int = 2048) -> List[Dict[str, Any]]:
    """
    Parse `/proc/net/nf_conntrack` on OpenWrt / Linux gateways to extract bidirectional byte counters
    for active TCP/UDP flows without spawning external subprocesses.
    """
    if not CONNTRACK_PROC_PATH.exists():
        return []
    entries: List[Dict[str, Any]] = []
    kv_re = re.compile(r"(\w+)=([^\s]+)")
    try:
        with CONNTRACK_PROC_PATH.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(entries) >= max_entries:
                    break
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                proto = parts[2].lower()
                if proto not in ("tcp", "udp"):
                    continue
                kvs = kv_re.findall(line)
                src_ips = [v for k, v in kvs if k == "src"]
                dst_ips = [v for k, v in kvs if k == "dst"]
                sports = [v for k, v in kvs if k == "sport"]
                dports = [v for k, v in kvs if k == "dport"]
                bytes_list = [v for k, v in kvs if k == "bytes"]
                pkts_list = [v for k, v in kvs if k == "packets"]
                if len(src_ips) >= 1 and len(dst_ips) >= 1 and len(sports) >= 1 and len(dports) >= 1:
                    entries.append(
                        {
                            "proto": proto,
                            "src": src_ips[0],
                            "dst": dst_ips[0],
                            "sport": int(sports[0]),
                            "dport": int(dports[0]),
                            "orig_bytes": int(bytes_list[0]) if len(bytes_list) >= 1 else 0,
                            "reply_bytes": int(bytes_list[1]) if len(bytes_list) >= 2 else 0,
                            "orig_pkts": int(pkts_list[0]) if len(pkts_list) >= 1 else 0,
                            "reply_pkts": int(pkts_list[1]) if len(pkts_list) >= 2 else 0,
                        }
                    )
    except Exception:
        return []
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="janusflow-openwrt-probe",
        description="JanusFlow Edge OpenWrt / Linux Gateway FlowSketch v2 Probe Agent",
    )
    ap.add_argument("--endpoint", default=None, help=f"Gateway URL (default: {DEFAULT_PUBLIC_ENDPOINT})")
    ap.add_argument("--api-key", default=None, help="API Key (or env JANUSFLOW_API_KEY / CLAW_API_KEY)")
    ap.add_argument("--secret", default=None, help="HMAC Sign Secret (or env JANUSFLOW_SIGN_SECRET / CLAW_SIGN_SECRET)")
    ap.add_argument("--iface", default="br-lan", help="OpenWrt capture interface (e.g. br-lan, eth0, pppoe-wan)")
    ap.add_argument("--device-id", default="openwrt-gw-01", help="Unique gateway identifier")
    ap.add_argument("--local-cidr", default="10.0.0.0/8", help="Comma-separated LAN CIDRs")
    ap.add_argument("--interval", type=int, default=60, help="Capture window in seconds (default 60)")
    ap.add_argument("--snaplen", type=int, default=256, help="Header snaplen in bytes (default 256)")
    ap.add_argument("--mode", choices=["both", "profile", "pcdn"], default="both")
    ap.add_argument("--include-conntrack", action="store_true", help="Attach /proc/net/nf_conntrack byte counters")
    ap.add_argument("--work-dir", default="/var/run/janusflow", help="In-memory working directory")
    ap.add_argument("--once", action="store_true", help="Run one window and exit")
    ap.add_argument("--self-test", action="store_true", help="Run offline FlowSketch v2 self-test and exit")
    args = ap.parse_args()

    if args.self_test:
        demo_pcap = build_synthetic_demo_pcap_bytes(include_tso_superframe=True)
        recs = parse_capture_bytes_to_flow_records(demo_pcap, filename="openwrt_selftest.pcap")
        print(
            json.dumps(
                {
                    "status": "ok",
                    "agent": "janusflow-openwrt-probe",
                    "flows_extracted": len(recs),
                    "sample_sni": recs[0].get("sni") if recs else None,
                    "conntrack_readable": CONNTRACK_PROC_PATH.exists(),
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
        timeout=60.0,
    )

    tcpdump_bin = shutil.which("tcpdump")
    if not tcpdump_bin:
        print(
            json.dumps(
                {
                    "status": "error",
                    "message": "tcpdump not found. Run: opkg update && opkg install tcpdump-mini",
                }
            ),
            file=sys.stderr,
        )
        return 1

    work_dir = Path(args.work_dir)
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        work_dir = Path("/tmp/janusflow_openwrt")
        work_dir.mkdir(parents=True, exist_ok=True)

    cycle = 0
    while True:
        cycle += 1
        pcap_p = work_dir / f"owrt_{os.getpid()}_{cycle}.pcap"
        fsk_p = work_dir / f"owrt_{os.getpid()}_{cycle}.v2.fsk.jsonl.gz"
        try:
            cmd = [
                tcpdump_bin,
                "-i",
                args.iface,
                "-nn",
                "-U",
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
                "pppoes",
                "or",
                "vlan",
            ]
            subprocess.run(cmd, capture_output=True, text=True)
            if not pcap_p.exists() or pcap_p.stat().st_size <= 24:
                if args.once:
                    return 0
                time.sleep(2.0)
                continue

            sketch_meta = convert_pcap_file_to_flowsketch_gz(pcap_p, output_path=fsk_p)
            pcap_p.unlink(missing_ok=True)

            fields: Dict[str, str] = {"device_id": args.device_id}
            if args.local_cidr.strip():
                fields["local_cidr"] = args.local_cidr.strip()
            if args.include_conntrack:
                ct_rows = snapshot_openwrt_conntrack()
                if ct_rows:
                    fields["conntrack_bytes_json"] = json.dumps(ct_rows, separators=(",", ":"))

            report: Dict[str, Any] = {
                "ts": int(time.time()),
                "cycle": cycle,
                "device_id": args.device_id,
                "iface": args.iface,
                "sketch_meta": sketch_meta,
            }
            if args.mode in ("both", "profile"):
                st_p, res_p = client.upload_multipart("/api/v2/traffic/profile-period", file_path=fsk_p, fields=fields)
                report["profile_status"] = st_p
                report["profile"] = res_p
            if args.mode in ("both", "pcdn"):
                st_c, res_c = client.upload_multipart("/api/v2/traffic/pcdn-scan", file_path=fsk_p, fields=fields)
                report["pcdn_status"] = st_c
                report["pcdn"] = res_c

            print(json.dumps(report, ensure_ascii=False))
        finally:
            pcap_p.unlink(missing_ok=True)
            fsk_p.unlink(missing_ok=True)

        if args.once:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
