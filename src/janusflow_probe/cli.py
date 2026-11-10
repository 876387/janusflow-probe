#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`janusflow-probe` — JanusFlow (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com)
Zero-Dependency Dual-Tower Encrypted Traffic Identification & Network Probe CLI:
    - `janusflow-probe auth login --sub cp_sub_v1_...`
    - `janusflow-probe usage`
    - `janusflow-probe sketch ./capture.pcap -o ./capture.v2.fsk.jsonl.gz`
    - `janusflow-probe profile ./capture.pcap --device-id openwrt-gw-01 [--local-cidr 10.0.0.0/8] [--local-sketch]`
    - `janusflow-probe pcdn-scan ./core_tap.pcap.gz --device-id core-tap-10g-01 [--local-cidr 10.0.0.0/8]`
    - `janusflow-probe timeline [capture.pcap --target-ip 10.0.0.25] [--device-id openwrt-gw-01 --window 3600]`
    - `janusflow-probe probe-openwrt --iface br-lan --device-id openwrt-gw-01 --interval 60`
    - `janusflow-probe probe-10g-tap --iface eth1 --device-id core-tap-10g-01 --interval 30 --enforce-offload-off`

Exit Codes:
  - `0`: Completed cleanly
  - `1`: Usage, argument, file-not-found, or authentication error
  - `3`: Quota exceeded (`ERR_QUOTA_EXCEEDED` / `ERR_PCDN_SCAN_QUOTA_EXCEEDED`)
  - `4`: Network or service unavailability
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional

from janusflow_probe import __version__
from janusflow_probe.client import (
    CRED_PATH,
    DEFAULT_PUBLIC_ENDPOINT,
    ClawNexusClient,
    load_credentials,
    save_credentials,
)
from janusflow_probe.flowsketch import (
    FSK_SCHEMA_VERSION_V2_PA,
    build_synthetic_demo_pcap_bytes,
    convert_pcap_file_to_flowsketch_gz,
    parse_capture_bytes_to_flow_records,
    verify_ethtool_offloads_disabled,
)

AUTO_FLOWSKETCH_THRESHOLD_BYTES = 6 * 1024 * 1024


def _build_client(args: argparse.Namespace) -> ClawNexusClient:
    creds = load_credentials(
        endpoint=getattr(args, "endpoint", None),
        api_key=getattr(args, "api_key", None),
        sign_secret=getattr(args, "secret", None),
        spki_pin=getattr(args, "spki_pin", None),
    )
    return ClawNexusClient(
        endpoint=creds["endpoint"],
        api_key=creds["api_key"],
        sign_secret=creds["sign_secret"],
        ca_cert=getattr(args, "ca_cert", None),
        spki_pins=creds["spki_pins"],
        pin_mode=getattr(args, "pin_mode", None),
        timeout=60.0,
    )


def _format_bytes_compact(num_bytes: int) -> str:
    b = max(0, int(num_bytes))
    if b >= 1024 * 1024 * 1024:
        return f"{b / (1024 ** 3):.2f}GB"
    if b >= 1024 * 1024:
        return f"{b / (1024 ** 2):.2f}MB"
    if b >= 1024:
        return f"{b / 1024.0:.1f}KB"
    return f"{b}B"


def _render_profile_table(resp: Dict[str, Any], sketch_meta: Optional[Dict[str, Any]] = None) -> str:
    res = resp.get("result", {})
    lines = [
        f"=== JanusFlow Dual-Tower Encrypted Traffic Profile (Device: {resp.get('device_id')} | Plane: {resp.get('access_plane')}) ===",
        f"Flows Analyzed : {res.get('n_flows', 0)} (Billed: {resp.get('flows_billed', res.get('n_flows', 0))} | Quota Remaining Today: {resp.get('probe_quota_remaining_today')})",
        f"Primary Verdict: {res.get('pred_pkg')} (Two-Stage OOD Gate Rejected: {res.get('is_ood_rejected')})",
    ]
    if sketch_meta is not None:
        lines.append(
            f"Local FlowSketch: {_format_bytes_compact(sketch_meta['input_bytes'])} -> "
            f"{_format_bytes_compact(sketch_meta['output_bytes'])} "
            f"({sketch_meta['compression_ratio']}x compression, {sketch_meta['flows_extracted']} flows, "
            f"TSO super-frames folded={sketch_meta.get('oversized_up_pkts_normalized', 0) + sketch_meta.get('oversized_down_pkts_normalized', 0)})"
        )
    if res.get("pred_app_name") or res.get("confidence_grade"):
        lines.append(
            f"App / Category : {res.get('pred_app_name', '-')} / {res.get('pred_category', '-')} "
            f"(Grade: {res.get('confidence_grade', '-')})"
        )
    top5 = res.get("top5") or []
    if top5:
        lines.append("--- Top-5 Dual-Tower Anchor Candidates ---")
        for idx, c in enumerate(top5, start=1):
            lines.append(
                f"  #{idx}  {c.get('package_name', ''):<36}  {c.get('app_name', ''):<18}  vote={c.get('vote_share', 0):.4f}"
            )
    recalled = res.get("recalled_known_apps") or []
    if recalled:
        lines.append("--- Recalled Known Applications (Multi-App Demux) ---")
        for r in recalled:
            lines.append(
                f"  + {r.get('package_name', ''):<36}  {r.get('app_name', ''):<18}  flows={r.get('flow_count', 0)}"
            )
    sdks = res.get("sdk_detections", [])
    if sdks:
        lines.append("--- Detected 3rd-Party SDK / Shared Infra Flows ---")
        for s in sdks:
            lines.append(f"  * {s.get('sdk_label'):<36} flows={s.get('flow_count')} conf={s.get('mean_confidence')}")
    pwin = resp.get("pcdn_window")
    if isinstance(pwin, dict):
        lines.append(
            f"--- Sliding-Window PCDN Telemetry: state={pwin.get('window_state')} "
            f"fragments={pwin.get('fragments_in_window')} seeding_endpoints={pwin.get('pcdn_seeding_endpoints_count', 0)} ---"
        )
    return "\n".join(lines)


def _render_pcdn_scan_table(resp: Dict[str, Any], sketch_meta: Optional[Dict[str, Any]] = None) -> str:
    scan = resp.get("scan") or {}
    lines = [
        f"=== JanusFlow PCDN 拓扑与包络技术检测台账 (设备: {resp.get('device_id')} | 接入面: {resp.get('access_plane')}) ===",
        (
            f"活跃终端数: {scan.get('active_local_endpoints', 0)} | "
            f"命中分片分发终端数: {scan.get('pcdn_seeding_endpoints_count', 0)} | "
            f"本次扣减配额: {resp.get('pcdn_scan_credits_deducted', 1)} "
            f"(剩余 pcdn_scan_credits: {resp.get('pcdn_scan_credits_remaining')})"
        ),
    ]
    if sketch_meta is not None:
        lines.append(
            f"本地 FlowSketch v2 预提取: {_format_bytes_compact(sketch_meta['input_bytes'])} -> "
            f"{_format_bytes_compact(sketch_meta['output_bytes'])} "
            f"(压缩比 {sketch_meta['compression_ratio']}x, 流记录 {sketch_meta['flows_extracted']} 条)"
        )
    header = "终端 IP | 客观技术等级 | 关联特征 | 上行/下行字节与比值 | 离散公网 /16 子网数 | 去重无域名对端 IP 数"
    lines.append("-" * 116)
    lines.append(header)
    lines.append("-" * 116)
    for ep in scan.get("endpoints", []):
        ul_dl_txt = (
            f"{_format_bytes_compact(ep.get('win_up_bytes', 0))} / "
            f"{_format_bytes_compact(ep.get('win_down_bytes', 0))} "
            f"({ep.get('ul_dl_bytes_ratio', 0.0):.2f}x)"
        )
        lines.append(
            f"{ep.get('local_ip', '')} | "
            f"{ep.get('verdict_level', '')} | "
            f"{ep.get('associated_features', '')} | "
            f"{ul_dl_txt} | "
            f"{ep.get('distinct_peer_subnet16', 0)} | "
            f"{ep.get('distinct_bare_peer_ips', 0)}"
        )
    return "\n".join(lines)


def _render_pcdn_timeline_table(resp: Dict[str, Any]) -> str:
    lines = [
        f"=== 设备 PCDN 窗口特征时间线 (设备: {resp.get('device_id')} | 最近 {resp.get('window_sec')}s | 事件数: {resp.get('pcdn_events_count', 0)}) ===",
        "-" * 116,
        "终端 IP | 客观技术等级 | 关联特征 | 上行/下行字节与比值 | 离散公网 /16 子网数 | 去重无域名对端 IP 数",
        "-" * 116,
    ]
    for item in resp.get("pcdn_endpoints_summary", []):
        ul_dl_txt = (
            f"{_format_bytes_compact(item.get('max_win_up_bytes', 0))} / "
            f"{_format_bytes_compact(item.get('max_win_down_bytes', 0))} "
            f"({item.get('max_ul_dl_bytes_ratio', 0.0):.2f}x)"
        )
        lines.append(
            f"{item.get('local_ip', '')} | "
            f"{item.get('latest_verdict_level', '')} | "
            f"{item.get('associated_features', '')} | "
            f"{ul_dl_txt} | "
            f"{item.get('max_distinct_peer_subnet16', 0)} | "
            f"{item.get('max_distinct_bare_peer_ips', 0)}"
        )
    return "\n".join(lines)


def _run_doctor(client: ClawNexusClient) -> int:
    checks: dict = {
        "cli_version": __version__,
        "python_version": sys.version.split()[0],
        "openssl_version": ssl.OPENSSL_VERSION,
        "tls13_supported": bool(getattr(ssl, "HAS_TLSv1_3", False)),
        "endpoint": client.endpoint,
        "pin_mode": client.pin_mode,
        "flowsketch_schema": FSK_SCHEMA_VERSION_V2_PA,
    }
    ok = sys.version_info >= (3, 9)

    if CRED_PATH.exists():
        mode_oct = stat.S_IMODE(os.stat(CRED_PATH).st_mode)
        checks["credentials_file"] = str(CRED_PATH)
        checks["credentials_permissions"] = f"0{mode_oct:o}"
        if os.name != "nt" and (mode_oct & 0o077) != 0:
            checks["credentials_warning"] = "Permissions broader than 0600; run chmod 600 ~/.clawnexus/credentials.json"
    else:
        checks["credentials_file"] = "not_configured (using env vars or anonymous doctor)"

    try:
        t0 = time.time()
        st, hdrs, _ = client.request_raw("GET", "/api/v1/health", require_auth=False, retries=1)
        rtt_ms = round((time.time() - t0) * 1000.0, 1)
        checks["health_http_status"] = st
        checks["rtt_ms"] = rtt_ms
        checks["peer_spki_sha256"] = client.last_peer_spki_sha256
        checks["spki_pin_matched"] = client.last_spki_pin_matched
        if st != 200:
            ok = False
        date_hdr = hdrs.get("date")
        if date_hdr:
            dt = email.utils.parsedate_to_datetime(date_hdr)
            skew_sec = round(abs(time.time() - dt.timestamp()), 2)
            checks["clock_skew_sec"] = skew_sec
            checks["clock_skew_ok"] = skew_sec <= 60.0
            if skew_sec > 60.0:
                ok = False
                checks["clock_warning"] = f"Clock skew {skew_sec}s exceeds ±60s HMAC v2 anti-replay window"
    except Exception as exc:
        ok = False
        checks["connection_error"] = str(exc)

    checks["status"] = "ok" if ok else "failed"
    print(json.dumps(checks, indent=2, ensure_ascii=False))
    return 0 if ok else 4


def _submit_traffic_file(
    client: ClawNexusClient,
    api_path: str,
    fpath: Path,
    device_id: str,
    local_cidr: str = "",
    force_local_sketch: bool = False,
) -> tuple[int, Dict[str, Any], Optional[Dict[str, Any]]]:
    is_already_sketch = fpath.name.endswith(".fsk.jsonl") or fpath.name.endswith(".fsk.jsonl.gz")
    need_local_sketch = (not is_already_sketch) and (
        bool(force_local_sketch) or fpath.stat().st_size > AUTO_FLOWSKETCH_THRESHOLD_BYTES
    )
    fields: Dict[str, str] = {"device_id": device_id}
    if local_cidr.strip():
        fields["local_cidr"] = local_cidr.strip()

    sketch_meta: Optional[Dict[str, Any]] = None
    if need_local_sketch:
        with tempfile.TemporaryDirectory(prefix="janusflow_fsk_") as tmp_dir:
            tmp_fsk = Path(tmp_dir) / f"{fpath.stem}.v2.fsk.jsonl.gz"
            sketch_meta = convert_pcap_file_to_flowsketch_gz(fpath, output_path=tmp_fsk)
            st, body = client.upload_multipart(api_path, file_path=tmp_fsk, fields=fields)
    else:
        st, body = client.upload_multipart(api_path, file_path=fpath, fields=fields)

    if sketch_meta is not None and isinstance(body, dict):
        body["local_flowsketch_preextract"] = sketch_meta
    return st, body, sketch_meta


def _run_probe_capture_loop(
    client: ClawNexusClient,
    probe_kind: str,
    iface: str,
    device_id: str,
    interval_sec: int,
    snaplen: int,
    local_cidr: str,
    mode: str,
    ring_mb: int = 16,
    enforce_offload_off: bool = False,
    bpf_filter: str = "ip or ip6 or vlan",
    once: bool = False,
    self_test: bool = False,
) -> int:
    if self_test:
        with tempfile.TemporaryDirectory(prefix="janusflow_probe_selftest_") as tmp_d:
            demo_pcap = Path(tmp_d) / "probe_selftest.pcap"
            demo_fsk = Path(tmp_d) / "probe_selftest.v2.fsk.jsonl.gz"
            demo_pcap.write_bytes(build_synthetic_demo_pcap_bytes(include_tso_superframe=True))
            meta = convert_pcap_file_to_flowsketch_gz(demo_pcap, output_path=demo_fsk)
            recs = parse_capture_bytes_to_flow_records(demo_fsk.read_bytes(), filename=demo_fsk.name)
            eth_check = verify_ethtool_offloads_disabled(
                "tcp-segmentation-offload: off\ngeneric-segmentation-offload: off\ngeneric-receive-offload: off\n"
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "probe_kind": probe_kind,
                        "iface": iface,
                        "device_id": device_id,
                        "fsk_version": meta["fsk_version"],
                        "flows_extracted": meta["flows_extracted"],
                        "roundtrip_records": len(recs),
                        "compression_ratio": meta["compression_ratio"],
                        "oversized_up_pkts_normalized": meta["oversized_up_pkts_normalized"],
                        "ethtool_offload_validator": eth_check["offload_state"],
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
        return 0

    tcpdump_bin = shutil.which("tcpdump")
    if not tcpdump_bin:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error_code": "ERR_TCPDUMP_NOT_FOUND",
                    "message": "tcpdump binary not found. On OpenWrt run: `opkg update && opkg install tcpdump-mini`; on Ubuntu/Debian run: `apt-get install -y tcpdump ethtool`.",
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1

    if probe_kind == "core_10g_tap":
        ethtool_bin = shutil.which("ethtool")
        if ethtool_bin:
            if enforce_offload_off:
                subprocess.run(
                    [ethtool_bin, "-K", iface, "tso", "off", "gso", "off", "gro", "off", "lro", "off"],
                    capture_output=True,
                    text=True,
                )
            k_res = subprocess.run([ethtool_bin, "-k", iface], capture_output=True, text=True)
            offload_audit = verify_ethtool_offloads_disabled(k_res.stdout)
            print(
                json.dumps(
                    {
                        "event": "10g_tap_nic_offload_audit",
                        "iface": iface,
                        "offload_state": offload_audit["offload_state"],
                        "compliant": offload_audit["compliant"],
                        "missing_or_enabled": offload_audit["missing_or_enabled"],
                        "note": "FlowSketch v2 (2.0-pa) adaptive MSS folding remains active as a second-line safeguard.",
                    },
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )

    cycle = 0
    while True:
        cycle += 1
        with tempfile.TemporaryDirectory(prefix=f"jf_{probe_kind}_") as work_dir:
            raw_pcap = Path(work_dir) / f"window_{cycle}.pcap"
            fsk_path = Path(work_dir) / f"window_{cycle}.v2.fsk.jsonl.gz"
            ring_kb = max(2048, int(ring_mb) * 1024)
            cmd = [
                tcpdump_bin,
                "-i",
                iface,
                "-nn",
                "-U",
                "-B",
                str(ring_kb),
                "-s",
                str(max(128, int(snaplen))),
                "-G",
                str(max(5, int(interval_sec))),
                "-W",
                "1",
                "-w",
                str(raw_pcap),
            ]
            if bpf_filter.strip():
                cmd.extend(bpf_filter.strip().split())

            t_start = time.time()
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if not raw_pcap.exists() or raw_pcap.stat().st_size <= 24:
                print(
                    json.dumps(
                        {
                            "event": "probe_window_empty",
                            "cycle": cycle,
                            "iface": iface,
                            "returncode": proc.returncode,
                            "stderr": (proc.stderr or "").strip()[-240:],
                        },
                        ensure_ascii=False,
                    ),
                    file=sys.stderr,
                )
                if once:
                    return 0 if proc.returncode == 0 else 1
                time.sleep(2.0)
                continue

            sketch_meta = convert_pcap_file_to_flowsketch_gz(raw_pcap, output_path=fsk_path)
            raw_pcap.unlink(missing_ok=True)

            fields: Dict[str, str] = {"device_id": device_id}
            if local_cidr.strip():
                fields["local_cidr"] = local_cidr.strip()

            out_record: Dict[str, Any] = {
                "event": "probe_window_completed",
                "probe_kind": probe_kind,
                "cycle": cycle,
                "device_id": device_id,
                "iface": iface,
                "window_sec": round(time.time() - t_start, 2),
                "sketch_meta": sketch_meta,
            }
            if mode in ("both", "profile"):
                st_p, body_p = client.upload_multipart("/api/v2/traffic/profile-period", file_path=fsk_path, fields=fields)
                out_record["profile_http_status"] = st_p
                out_record["profile_response"] = body_p
            if mode in ("both", "pcdn"):
                st_c, body_c = client.upload_multipart("/api/v2/traffic/pcdn-scan", file_path=fsk_path, fields=fields)
                out_record["pcdn_http_status"] = st_c
                out_record["pcdn_response"] = body_c

            print(json.dumps(out_record, indent=2, ensure_ascii=False))
            if once:
                return 0


def main() -> None:

    parser = argparse.ArgumentParser(
        prog="janusflow-probe",
        description=(
            "JanusFlow Probe (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com) — "
            "Dual-Tower Encrypted Traffic Identification, PCDN Topology Scan & OpenWrt / 10G Optical TAP Probe CLI"
        ),
    )
    parser.add_argument("--version", action="version", version=f"janusflow-probe {__version__}")
    parser.add_argument("--endpoint", default=None, help=f"Gateway URL (default: {DEFAULT_PUBLIC_ENDPOINT})")
    parser.add_argument("--api-key", default=None, help="Commercial API Key (cnx_live_* / cp_live_* or env JANUSFLOW_API_KEY)")
    parser.add_argument("--secret", default=None, help="HMAC-SHA256 Sign Secret (sec_* or env JANUSFLOW_SIGN_SECRET)")
    parser.add_argument("--ca-cert", default=None, help="Optional custom TLS CA PEM path")
    parser.add_argument("--spki-pin", default=None, help="Optional comma-separated SPKI SHA-256 Base64 pins")
    parser.add_argument("--pin-mode", choices=["ca", "strict", "off"], default=None, help="TLS pin policy (default: strict)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check Python/OpenSSL TLS 1.3 support, certificate chain, and ±60s clock skew")
    sub.add_parser("usage", help="Query remaining daily traffic-flow quota & PCDN scan credits of the unified JanusFlow API Key")

    p_auth = sub.add_parser("auth", help="Manage CLI authentication credentials (unified JanusFlow API Key)")
    auth_sub = p_auth.add_subparsers(dest="auth_cmd", required=True)
    p_login = auth_sub.add_parser("login", help="Store APIKEY, HMAC secret (or cp_sub_v1_ subscription token) in ~/.clawnexus/credentials.json")
    p_login.add_argument("--endpoint", default=DEFAULT_PUBLIC_ENDPOINT, help=f"Service endpoint (default: {DEFAULT_PUBLIC_ENDPOINT})")
    p_login.add_argument("--api-key", default=None, help="Commercial API Key (cnx_live_* / cp_live_*)")
    p_login.add_argument("--secret", default=None, help="HMAC-SHA256 Sign Secret (sec_*)")
    p_login.add_argument("--sub", default=None, help="One-click subscription token (cp_sub_v1_...) from portal purchase/redeem")
    p_login.add_argument("--spki-pin", default=None)
    auth_sub.add_parser("verify", help="Verify TLS 1.3 handshake, HMAC v2 authentication, and traffic-flow / PCDN quotas")

    # === Dual-Tower Encrypted Traffic Identification & Network Probes ===
    p_sk = sub.add_parser(
        "sketch",
        help="[Traffic Service] Pre-extract local PCAP/PCAPNG into compact TSO/GSO-normalized FlowSketch v2 (.fsk.jsonl.gz)",
    )
    p_sk.add_argument("input", nargs="?", help="Input .pcap / .pcap.gz / .pcapng file")
    p_sk.add_argument("-o", "--output", default=None, help="Output .v2.fsk.jsonl.gz path")
    p_sk.add_argument("--check-ethtool-file", default=None, help="Optional path to `ethtool -k` output text to assert tso/gso/gro=off")
    p_sk.add_argument("--self-test", action="store_true", help="Run offline FlowSketch v2 + TSO super-frame folding self-test")

    p_prof = sub.add_parser(
        "profile",
        help="[Traffic Service] Identify encrypted app flows, 17-class SDKs & OOD gate status from PCAP or FlowSketch (.fsk.jsonl.gz)",
    )
    p_prof.add_argument("input", help="Path to capture file (.pcap, .pcap.gz, .pcapng, .fsk.jsonl.gz)")
    p_prof.add_argument("--device-id", default="edge-probe-01", help="Logical probe / router identifier")
    p_prof.add_argument("--local-cidr", default="", help="Optional comma-separated local CIDR blocks (e.g. 10.0.0.0/8)")
    p_prof.add_argument("--local-sketch", action="store_true", help="Pre-extract .fsk.jsonl.gz locally before upload (auto for >6 MB)")
    p_prof.add_argument("--format", choices=["json", "table"], default="table")

    p_pcdn = sub.add_parser(
        "pcdn-scan",
        help="[Traffic Service] Scan PCAP or FlowSketch for multi-subnet PCDN seeding topology & uplink/downlink envelope features",
    )
    p_pcdn.add_argument("input", help="Path to capture file (.pcap, .pcap.gz, .pcapng, .fsk.jsonl.gz)")
    p_pcdn.add_argument("--device-id", default="core-tap-01", help="Logical probe / router identifier")
    p_pcdn.add_argument("--local-cidr", default="", help="Optional comma-separated local CIDR blocks (e.g. 10.0.0.0/8)")
    p_pcdn.add_argument("--local-sketch", action="store_true", help="Pre-extract .fsk.jsonl.gz locally before upload (auto for >6 MB)")
    p_pcdn.add_argument("--format", choices=["json", "table"], default="table")

    p_tl = sub.add_parser(
        "timeline",
        help="[Traffic Service] Reconstruct per-IP chronological timeline from capture file or query probe sliding-window timeline",
    )
    p_tl.add_argument("input", nargs="?", default=None, help="Optional capture file (.pcap, .pcapng, .fsk.jsonl.gz) for timeline reconstruction")
    p_tl.add_argument("--target-ip", default="", help="Optional internal endpoint IP filter (e.g. 10.0.0.25)")
    p_tl.add_argument("--device-id", default="edge-probe-01")
    p_tl.add_argument("--window", type=int, default=3600, help="Lookback window in seconds (default 3600)")
    p_tl.add_argument("--pcdn-only", action="store_true", help="Filter timeline to PCDN sliding-window & scan events only")
    p_tl.add_argument("--local-sketch", action="store_true", help="Pre-extract .fsk.jsonl.gz locally before upload")
    p_tl.add_argument("--out", default=None, help="Optional JSON output file path")
    p_tl.add_argument("--format", choices=["json", "table"], default="table")

    p_owrt = sub.add_parser(
        "probe-openwrt",
        help="[Edge Probe] Run continuous lightweight OpenWrt / Linux LAN gateway ring-buffer FlowSketch probe",
    )
    p_owrt.add_argument("--iface", default="br-lan", help="Capture interface on OpenWrt router (e.g. br-lan, eth0, pppoe-wan)")
    p_owrt.add_argument("--device-id", default="openwrt-edge-01", help="Probe identifier reported to JanusFlow")
    p_owrt.add_argument("--interval", type=int, default=60, help="Capture window duration in seconds (default 60)")
    p_owrt.add_argument("--snaplen", type=int, default=256, help="Packet header snaplen in bytes (default 256, payload discarded locally)")
    p_owrt.add_argument("--local-cidr", default="10.0.0.0/8", help="Local LAN CIDR blocks")
    p_owrt.add_argument("--mode", choices=["both", "profile", "pcdn"], default="both")
    p_owrt.add_argument("--bpf", default="ip or ip6 or pppoes", help="BPF capture filter")
    p_owrt.add_argument("--once", action="store_true", help="Run a single capture window and exit")
    p_owrt.add_argument("--self-test", action="store_true", help="Run offline OpenWrt probe pipeline self-test")

    p_tap = sub.add_parser(
        "probe-10g-tap",
        help="[Core 10G Probe] Run high-throughput 10G/40G Optical TAP / Switch SPAN mirror probe with NIC offload audit",
    )
    p_tap.add_argument("--iface", default="eth1", help="Dedicated 10G/40G optical TAP or SPAN mirror RX interface")
    p_tap.add_argument("--device-id", default="core-10g-tap-01", help="Core probe identifier reported to JanusFlow")
    p_tap.add_argument("--interval", type=int, default=30, help="Capture window slice in seconds (default 30)")
    p_tap.add_argument("--snaplen", type=int, default=256, help="Packet header snaplen in bytes (default 256)")
    p_tap.add_argument("--ring-mb", type=int, default=256, help="Kernel AF_PACKET ring buffer size in MB (default 256)")
    p_tap.add_argument("--local-cidr", default="10.0.0.0/8", help="Internal subscriber CIDR blocks")
    p_tap.add_argument("--enforce-offload-off", action="store_true", help="Automatically run `ethtool -K <iface> tso off gso off gro off lro off`")
    p_tap.add_argument("--mode", choices=["both", "profile", "pcdn"], default="both")
    p_tap.add_argument("--bpf", default="ip or ip6 or vlan", help="BPF capture filter (supports 802.1Q VLAN / QinQ / VXLAN)")
    p_tap.add_argument("--once", action="store_true", help="Run a single capture window and exit")
    p_tap.add_argument("--self-test", action="store_true", help="Run offline 10G TAP probe pipeline & TSO normalization self-test")

    args = parser.parse_args()

    if args.cmd == "sketch":
        if args.self_test:
            demo_bytes = build_synthetic_demo_pcap_bytes(include_tso_superframe=True)
            recs = parse_capture_bytes_to_flow_records(demo_bytes, filename="demo.pcap")
            eth_ok = verify_ethtool_offloads_disabled(
                "tcp-segmentation-offload: off\ngeneric-segmentation-offload: off\ngeneric-receive-offload: off\n"
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "fsk_version": FSK_SCHEMA_VERSION_V2_PA,
                        "flows_extracted": len(recs),
                        "sample_sni": recs[0].get("sni") if recs else None,
                        "sample_est_mss": recs[0].get("est_mss") if recs else None,
                        "oversized_up_pkts_folded": recs[0].get("oversized_up_pkts") if recs else 0,
                        "oversized_up_equiv_segs": recs[0].get("oversized_up_equiv_segs") if recs else 0,
                        "ethtool_validator_ok": eth_ok["compliant"],
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return
        if not args.input:
            parser.error("`sketch` requires an input file path (or pass `--self-test`)")
        in_p = Path(args.input)
        if not in_p.exists():
            print(json.dumps({"status": "error", "message": f"File not found: {in_p}"}), file=sys.stderr)
            sys.exit(1)
        out_p = Path(args.output) if args.output else None
        meta = convert_pcap_file_to_flowsketch_gz(in_p, output_path=out_p)
        if args.check_ethtool_file:
            eth_txt = Path(args.check_ethtool_file).read_text(encoding="utf-8", errors="ignore")
            meta["ethtool_offload_check"] = verify_ethtool_offloads_disabled(eth_txt)
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return

    if args.cmd == "auth" and args.auth_cmd == "login":
        eff_ep = args.endpoint or DEFAULT_PUBLIC_ENDPOINT
        eff_key = args.api_key
        eff_sec = args.secret
        eff_pin = args.spki_pin
        if getattr(args, "sub", None):
            import base64
            tok = args.sub.strip()
            if tok.startswith("clawprobe://") and "sub=" in tok:
                tok = tok.split("sub=", 1)[1].split("&", 1)[0]
            if not tok.startswith("cp_sub_v1_"):
                parser.error("Invalid --sub token (expected cp_sub_v1_...)")
            b64_part = tok[len("cp_sub_v1_") :]
            pad = "=" * ((4 - len(b64_part) % 4) % 4)
            sub_obj = json.loads(base64.urlsafe_b64decode(b64_part + pad).decode("utf-8"))
            eff_ep = sub_obj.get("e") or eff_ep
            eff_key = sub_obj.get("k")
            eff_sec = sub_obj.get("s")
            eff_pin = sub_obj.get("p") or eff_pin
        if not eff_key or not eff_sec:
            parser.error("Provide either `--sub cp_sub_v1_...` or both `--api-key` and `--secret`")
        saved = save_credentials(eff_ep, eff_key, eff_sec, spki_pin=eff_pin)
        print(
            json.dumps(
                {
                    "status": "saved",
                    "credentials_file": str(saved),
                    "endpoint": (eff_ep or DEFAULT_PUBLIC_ENDPOINT).rstrip("/"),
                    "spki_pinning": "strict" if eff_pin else "ca_chain_verified",
                    "unified_services": ["dual_tower_traffic_identification", "pcdn_scan", "openwrt_edge_probe", "core_10g_tap_probe"],
                },
                indent=2,
            )
        )
        return

    client = _build_client(args)

    if args.cmd == "doctor":
        sys.exit(_run_doctor(client))

    if args.cmd == "usage":
        st, body = client.request_json("GET", "/api/v1/usage/summary")
        print(json.dumps(body, indent=2, ensure_ascii=False))
        sys.exit(0 if st == 200 else 1)

    if args.cmd == "auth" and args.auth_cmd == "verify":
        st, body = client.request_json("GET", "/api/v1/auth/verify")
        print(json.dumps(body, indent=2, ensure_ascii=False))
        sys.exit(0 if st == 200 else 1)

    if args.cmd == "profile":
        fpath = Path(args.input)
        if not fpath.exists():
            print(json.dumps({"status": "error", "message": f"File not found: {fpath}"}), file=sys.stderr)
            sys.exit(1)
        st, body, sketch_meta = _submit_traffic_file(
            client,
            "/api/v2/traffic/profile-period",
            fpath=fpath,
            device_id=args.device_id,
            local_cidr=args.local_cidr,
            force_local_sketch=args.local_sketch,
        )
        if st != 200:
            print(json.dumps(body, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
        if args.format == "table":
            print(_render_profile_table(body, sketch_meta=sketch_meta))
        else:
            print(json.dumps(body, indent=2, ensure_ascii=False))
        return

    if args.cmd == "pcdn-scan":
        fpath = Path(args.input)
        if not fpath.exists():
            print(json.dumps({"status": "error", "message": f"File not found: {fpath}"}), file=sys.stderr)
            sys.exit(1)
        st, body, sketch_meta = _submit_traffic_file(
            client,
            "/api/v2/traffic/pcdn-scan",
            fpath=fpath,
            device_id=args.device_id,
            local_cidr=args.local_cidr,
            force_local_sketch=args.local_sketch,
        )
        if st != 200:
            print(json.dumps(body, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
        if args.format == "table":
            print(_render_pcdn_scan_table(body, sketch_meta=sketch_meta))
        else:
            print(json.dumps(body, indent=2, ensure_ascii=False))
        return

    if args.cmd == "timeline":
        if getattr(args, "input", None):
            fpath = Path(args.input)
            if not fpath.exists():
                print(json.dumps({"status": "error", "message": f"File not found: {fpath}"}), file=sys.stderr)
                sys.exit(1)
            fields = {"device_id": args.device_id}
            if getattr(args, "target_ip", ""):
                fields["target_ip"] = args.target_ip.strip()
            is_sketch = fpath.name.endswith(".fsk.jsonl") or fpath.name.endswith(".fsk.jsonl.gz")
            if (not is_sketch) and (args.local_sketch or fpath.stat().st_size > AUTO_FLOWSKETCH_THRESHOLD_BYTES):
                with tempfile.TemporaryDirectory(prefix="janusflow_tl_") as tmp_dir:
                    tmp_fsk = Path(tmp_dir) / f"{fpath.stem}.v2.fsk.jsonl.gz"
                    convert_pcap_file_to_flowsketch_gz(fpath, output_path=tmp_fsk)
                    st, body = client.upload_multipart("/api/v2/traffic/timeline", file_path=tmp_fsk, fields=fields)
            else:
                st, body = client.upload_multipart("/api/v2/traffic/timeline", file_path=fpath, fields=fields)
        else:
            q_params: Dict[str, Any] = {"device_id": args.device_id, "window_sec": args.window}
            if args.pcdn_only:
                q_params["pcdn_only"] = "true"
            qs = urllib.parse.urlencode(q_params)
            st, body = client.request_json("GET", f"/api/v2/traffic/timeline?{qs}")
        if st != 200:
            print(json.dumps(body, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
        if getattr(args, "out", None):
            Path(args.out).write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
        if args.format == "table":
            if args.pcdn_only:
                print(_render_pcdn_timeline_table(body))
            else:
                lines = [
                    f"=== JanusFlow Device Timeline ({body.get('device_id')} | Last {body.get('window_sec', args.window)}s | Periods={body.get('total_periods', 1)}) ==="
                ]
                for a in body.get("active_apps_summary", []):
                    lines.append(
                        f"  * {a['package_name']:<36} {a['app_name']:<18} periods={a['periods_active']} flows={a['total_flows']} max_conf={a['max_confidence']}"
                    )
                print("\n".join(lines))
        else:
            print(json.dumps(body, indent=2, ensure_ascii=False))
        return

    if args.cmd == "probe-openwrt":
        sys.exit(
            _run_probe_capture_loop(
                client=client,
                probe_kind="openwrt_edge",
                iface=args.iface,
                device_id=args.device_id,
                interval_sec=args.interval,
                snaplen=args.snaplen,
                local_cidr=args.local_cidr,
                mode=args.mode,
                ring_mb=8,
                enforce_offload_off=False,
                bpf_filter=args.bpf,
                once=args.once,
                self_test=args.self_test,
            )
        )

    if args.cmd == "probe-10g-tap":
        sys.exit(
            _run_probe_capture_loop(
                client=client,
                probe_kind="core_10g_tap",
                iface=args.iface,
                device_id=args.device_id,
                interval_sec=args.interval,
                snaplen=args.snaplen,
                local_cidr=args.local_cidr,
                mode=args.mode,
                ring_mb=args.ring_mb,
                enforce_offload_off=args.enforce_offload_off,
                bpf_filter=args.bpf,
                once=args.once,
                self_test=args.self_test,
            )
        )



if __name__ == "__main__":
    main()
