import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from janusflow_probe import __version__
from janusflow_probe.client import (
    ClawNexusClient,
    DEFAULT_PUBLIC_ENDPOINT,
    canonicalize_path_and_query,
    compute_hmac_signature_v2,
)
from janusflow_probe.flowsketch import (
    FSK_SCHEMA_VERSION_V2_PA,
    build_synthetic_demo_pcap_bytes,
    convert_pcap_file_to_flowsketch_gz,
    parse_capture_bytes_to_flow_records,
    parse_tls_client_hello_sni_alpn,
    verify_ethtool_offloads_disabled,
)


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "janusflow_probe", *args],
        cwd=str(SRC_DIR),
        capture_output=True,
        text=True,
        check=True,
    )


class TestJanusFlowProbeOffline(unittest.TestCase):
    def test_version_and_defaults(self):
        self.assertEqual(__version__, "0.1.0")
        self.assertEqual(DEFAULT_PUBLIC_ENDPOINT, "https://www.atooli.com")
        self.assertIn("janusflow-probe 0.1.0", _run_cli("--version").stdout)

    def test_cli_exposes_only_traffic_and_probe_commands(self):
        help_txt = _run_cli("--help").stdout
        for cmd in ("sketch", "profile", "pcdn-scan", "timeline", "probe-openwrt", "probe-10g-tap", "usage", "auth"):
            self.assertIn(cmd, help_txt)
        for apk_cmd in ("analyze", "reclaim", "desktop"):
            self.assertNotIn(apk_cmd, help_txt)

    def test_hmac_canonical_signing(self):
        self.assertEqual(canonicalize_path_and_query("/api/v1/quota?b=2&a=1"), "/api/v1/quota?a=1&b=2")
        sig = compute_hmac_signature_v2(
            sign_secret="sec_demo_secret_0001",
            method="GET",
            path_with_query="/api/v2/traffic/timeline?window_sec=3600&device_id=gw01",
            timestamp="1700000000",
            nonce="00112233445566778899aabb",
            full_raw_body_sha256=hashlib.sha256(b"").hexdigest(),
        )
        self.assertEqual(len(sig), 64)

    def test_missing_credentials_raises_value_error(self):
        client = ClawNexusClient(endpoint="https://www.atooli.com", api_key="", sign_secret="")
        with self.assertRaises(ValueError):
            client.request_raw("GET", "/api/v1/usage/summary", b"", require_auth=True)

    def test_flowsketch_roundtrip_sni_and_tso_folding(self):
        with tempfile.TemporaryDirectory() as td:
            pcap = Path(td) / "demo.pcap"
            fsk = Path(td) / "demo.v2.fsk.jsonl.gz"
            pcap.write_bytes(build_synthetic_demo_pcap_bytes(include_tso_superframe=True))
            meta = convert_pcap_file_to_flowsketch_gz(pcap, output_path=fsk)
            self.assertEqual(meta["fsk_version"], FSK_SCHEMA_VERSION_V2_PA)
            self.assertGreaterEqual(meta["flows_extracted"], 1)
            recs = parse_capture_bytes_to_flow_records(fsk.read_bytes(), filename=fsk.name)
            self.assertEqual(recs[0].get("sni"), "api.janusflow.net")
            self.assertGreaterEqual(int(recs[0].get("oversized_up_pkts") or 0), 1)

    def test_tls_sni_parser_rejects_garbage(self):
        self.assertEqual(parse_tls_client_hello_sni_alpn(b"\x16\x03\x01\x00\x05hello"), (None, None))
        self.assertEqual(parse_tls_client_hello_sni_alpn(b""), (None, None))

    def test_ethtool_offload_validator(self):
        ok = verify_ethtool_offloads_disabled(
            "tcp-segmentation-offload: off\ngeneric-segmentation-offload: off\ngeneric-receive-offload: off\n"
        )
        self.assertTrue(ok["compliant"])
        bad = verify_ethtool_offloads_disabled("tcp-segmentation-offload: on\ngeneric-receive-offload: on\n")
        self.assertFalse(bad["compliant"])

    def test_cli_and_probe_agent_self_tests(self):
        for subcmd in ("sketch", "probe-openwrt", "probe-10g-tap"):
            out = _run_cli(subcmd, "--self-test").stdout
            self.assertIn('"status": "ok"', out)
            self.assertIn('"2.0-pa"', out)
        for script_rel in (
            Path("probes/openwrt_edge/openwrt_probe_agent.py"),
            Path("probes/core_10g_tap/core_10g_tap_agent.py"),
        ):
            proc = subprocess.run(
                [sys.executable, str(ROOT_DIR / script_rel), "--self-test"],
                cwd=str(ROOT_DIR),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn('"status": "ok"', proc.stdout)

    def test_zero_internal_ip_or_secret_leakage(self):
        forbidden_tokens = [
            "192.168.", "122.224.", "218.75.", "112.124.", "172.30.",
            "4060", "5000", "arm11", "cn_arm", "node11", "node_agent", "pool_manager",
            "nftables", "xt_nflog", "nflog", "skuid", "tmpfs", "clawbox", "fs-net",
            "byteetbert", "qwen", "redroid", "tnt_",
        ]
        patterns = ("*.py", "*.md", "*.sh", "*.init", "*.service", "*.toml", "*.yml")
        scan_targets = []
        for pat in patterns:
            scan_targets.extend(p for p in ROOT_DIR.rglob(pat) if ".git" not in p.parts and "tests" not in p.parts)
        self.assertGreater(len(scan_targets), 10)
        for path in scan_targets:
            content = path.read_text(encoding="utf-8").lower()
            for token in forbidden_tokens:
                self.assertNotIn(token.lower(), content, f"Forbidden internal token {token!r} found in {path}")


if __name__ == "__main__":
    unittest.main()
