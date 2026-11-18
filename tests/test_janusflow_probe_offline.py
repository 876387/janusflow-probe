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
        forbidden_window_hashes = {
            4: frozenset([
                "f9a75ecb0e5e127ed6917a563840dd2a33d661d385f9808f0547d188883a01d1",
                "0f8eb4b72b6e0c9e88b388eb967b49e067ef1004bf07bffc22c3acb13b43580a",
                "67f2d22514622d1be30c14ee9f3cb104503a159a33a656ca91a1953aa9616429",
                "1ab8b7f3160763c3ad6563287ef02a6022703117f43a94130f84c2e7ed3d367f",
            ]),
            5: frozenset([
                "9d20b602fbe5b565409aa4e64553bf531d75dd30ba9d0fdc2440ddc07e16999f",
                "064c28496762af7592c2d84e7acd32e95c8fdb2e09602e50a217b449201272d8",
                "c392fb854c31498c87f44406813903470382477010f878554ee4a4edc8cc524f",
                "02dae179e16841345a4e5cb7996e022ea6f45aeb4cbfa4811a76934328c2d24e",
            ]),
            6: frozenset([
                "c7496688a99973b04fee89173591f09cd1d650bd9def3a3a47ae36edbd277522",
                "2cb5049d289d9b03fbe6383613d680969fef82c092e583e80c258b3eb7024399",
                "c9e0a40ab5458b21622c05c24068a1bcd94642f86814729b9f3796590abfcc55",
            ]),
            7: frozenset([
                "a35906a5b5e2d3b78bd2513a9fbb4965726f949cd6220648984deb8bd86fda62",
                "6dbe9d04efa48bf698d72c1df6829e3c7837219a7869a35f91cc74c5b195052b",
                "538dcececb7751af5f51e2203591efc1d48cc586bbd9c991bb67c5b99fbc863b",
                "badc57e9a107c1e794a910fabdc6b80b22897525ef735cedf15748e0cef975d7",
            ]),
            8: frozenset([
                "89717ddba1be520eed9b14a8bacfa507b79608b04b7e1b1360a18183cdab4c1d",
                "faa8690ae801ec25cc668357e6e1e441916e7b4df54abd236f33b219f65316a8",
                "f31006e706fcc58856f733c46fbe7c9618908e7ae476fa3fe47ab58413503957",
                "c7ecb245374fc418d6290e8a67dad19032efd73f8f9a77b9ddacfa24b1d4b7af",
                "ac8cc19bba56cb1b39e99cb78ef1ddd38ea7b6e22a7996c9d06538dc2bb98650",
                "cfe01afd94ec594ce78ee7450f526145d1f83f5d798081b0ab9d1f5a8f93097e",
            ]),
            10: frozenset([
                "071366614492cac29cf0a56532f028a52942ee837b0394e1345efe11bec563ff",
                "90af2fc6d00f38600e023fc3cce599d6724edc949201dd07912231ddfa6c3540",
            ]),
            11: frozenset([
                "9a139a5d99d45485d6eb802214d7d748d99325092f82da93f0afdc8a4ca0901c",
            ]),
            12: frozenset([
                "c309821f889a0a17198e1ea6abc37846434581fe28523f43806191ffe88e96fd",
            ]),
            16: frozenset([
                "667ecbd06bb0e06021f89ecf77222cadb715fdc8835abdb02d9b20dec8fc3af9",
                "d503ca33bbd2114fcb130424e398afa3d81a37c89dfc08480333cd8230b5aa4b",
            ]),
        }
        patterns = ("*.py", "*.md", "*.sh", "*.init", "*.service", "*.toml", "*.yml")
        scan_targets = []
        for pat in patterns:
            scan_targets.extend(p for p in ROOT_DIR.rglob(pat) if ".git" not in p.parts and "tests" not in p.parts)
        self.assertGreater(len(scan_targets), 10)
        for path in scan_targets:
            content = path.read_text(encoding="utf-8").lower()
            n_chars = len(content)
            for win_len, target_hashes in forbidden_window_hashes.items():
                if n_chars < win_len:
                    continue
                unique_windows = {
                    content[i : i + win_len]
                    for i in range(n_chars - win_len + 1)
                    if ("0" <= content[i] <= "9") or ("a" <= content[i] <= "z")
                }
                for sub in unique_windows:
                    if not sub.isascii():
                        continue
                    digest = hashlib.sha256(sub.encode("utf-8")).hexdigest()
                    self.assertNotIn(
                        digest,
                        target_hashes,
                        f"Forbidden internal token hash {digest[:12]}... matched in {path}",
                    )


if __name__ == "__main__":
    unittest.main()
