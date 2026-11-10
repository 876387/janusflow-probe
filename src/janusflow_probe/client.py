#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawProbe — Zero-dependency stdlib TLS 1.3 + Certificate Chain / SPKI Verification +
Canonical HMAC-SHA256 v2 (Sorted Query + Full Raw HTTP Body) Anti-Replay HTTP Client.

Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
import time
import urllib.parse
from pathlib import Path
from typing import Any

CRED_PATH = Path(os.path.expanduser("~/.clawnexus/credentials.json"))
DEFAULT_PUBLIC_ENDPOINT = "https://www.atooli.com"

# Default SPKI SHA-256 Pins for https://www.atooli.com:
#   1. DigiCert Intermediate CA (Encryption Everywhere DV TLS CA - G2) — survives leaf cert rotation
#   2. DigiCert Global Root G2 — root trust anchor SPKI
#   3. www.atooli.com current leaf SPKI
#   4. Dedicated edge endpoint leaf SPKI
#   5. Dedicated edge root CA SPKI
DEFAULT_PINNED_SPKI_SHA256: tuple[str, ...] = (
    "gxeKFFaZ2HFJIsTdTjEl6nVo3ckTCX+qzRMqb9Xoa1w=",
    "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
    "h3mQK/w8dMmMne2+T0gN9L5DAL5BrhfskqFXjK5oOSo=",
    "PHijXDkakE3X7ORsNTDl9Gu+Dp2i30HnJgbkZ5Y++3g=",
    "sRUaJLJf+ABzALUcKExGeCXTsJv0q3jjywUYeGtWmFs=",
)

EMBEDDED_PUBLIC_CA_CHAIN_PEM = """-----BEGIN CERTIFICATE-----
MIIEqjCCA5KgAwIBAgIQDeD/te5iy2EQn2CMnO1e0zANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xNzExMjcxMjQ2NDBaFw0yNzExMjcxMjQ2NDBaMG4xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xLTArBgNVBAMTJEVuY3J5cHRpb24gRXZlcnl3aGVyZSBEViBUTFMgQ0EgLSBH
MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO8Uf46i/nr7pkgTDqnE
eSIfCFqvPnUq3aF1tMJ5hh9MnO6Lmt5UdHfBGwC9Si+XjK12cjZgxObsL6Rg1njv
NhAMJ4JunN0JGGRJGSevbJsA3sc68nbPQzuKp5Jc8vpryp2mts38pSCXorPR+sch
QisKA7OSQ1MjcFN0d7tbrceWFNbzgL2csJVQeogOBGSe/KZEIZw6gXLKeFe7mupn
NYJROi2iC11+HuF79iAttMc32Cv6UOxixY/3ZV+LzpLnklFq98XORgwkIJL1HuvP
ha8yvb+W6JislZJL+HLFtidoxmI7Qm3ZyIV66W533DsGFimFJkz3y0GeHWuSVMbI
lfsCAwEAAaOCAU8wggFLMB0GA1UdDgQWBBR435GQX+7erPbFdevVTFVT7yRKtjAf
BgNVHSMEGDAWgBROIlQgGJXm427mD/r6uRLtBhePOTAOBgNVHQ8BAf8EBAMCAYYw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8C
AQAwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
Y2VydC5jb20wQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQu
Y29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG
/WwBAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
MAgGBmeBDAECATANBgkqhkiG9w0BAQsFAAOCAQEAoBs1eCLKakLtVRPFRjBIJ9LJ
L0s8ZWum8U8/1TMVkQMBn+CPb5xnCD0GSA6L/V0ZFrMNqBirrr5B241OesECvxIi
98bZ90h9+q/X5eMyOD35f8YTaEMpdnQCnawIwiHx06/0BfiTj+b/XQih+mqt3ZXe
xNCJqKexdiB2IWGSKcgahPacWkk/BAQFisKIFYEqHzV974S3FAz/8LIfD58xnsEN
GfzyIDkH3JrwYZ8caPTf6ZX9M1GrISN8HnWTtdNCH2xEajRa/h9ZBXjUyFKQrGk2
n2hcLrfZSbynEC/pSw/ET7H5nWwckjmAJ1l9fcnbqkU/pf6uMQmnfl0JQjJNSg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
"""


class SPKIPinMismatchError(ssl.SSLCertVerificationError):
    """Raised when the peer TLS 1.3 certificate SPKI SHA-256 fingerprint does not match pinned SPKI hashes."""


def _read_asn1_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Parse one ASN.1 DER TLV -> (tag, header_start, value_start, next_offset)."""
    if offset >= len(data):
        raise ValueError("Truncated ASN.1 DER at tag")
    tag = data[offset]
    if offset + 1 >= len(data):
        raise ValueError("Truncated ASN.1 DER at length")
    first_len = data[offset + 1]
    if (first_len & 0x80) == 0:
        length = first_len
        val_start = offset + 2
    else:
        num_len_bytes = first_len & 0x7F
        if num_len_bytes == 0 or num_len_bytes > 4 or offset + 2 + num_len_bytes > len(data):
            raise ValueError("Invalid ASN.1 DER length octets")
        length = int.from_bytes(data[offset + 2 : offset + 2 + num_len_bytes], "big")
        val_start = offset + 2 + num_len_bytes
    next_off = val_start + length
    if next_off > len(data):
        raise ValueError("Truncated ASN.1 DER value")
    return tag, offset, val_start, next_off


def extract_spki_der_from_x509_der(cert_der: bytes) -> bytes:
    """Extract raw DER `SubjectPublicKeyInfo` (`RFC 5280 §4.1`) from an X.509 DER certificate using pure stdlib."""
    c_tag, _, c_val, _ = _read_asn1_tlv(cert_der, 0)
    if c_tag != 0x30:
        raise ValueError("X.509 certificate outer element is not SEQUENCE")
    tbs_tag, _, tbs_val, tbs_end = _read_asn1_tlv(cert_der, c_val)
    if tbs_tag != 0x30:
        raise ValueError("X.509 tbsCertificate is not SEQUENCE")

    pos = tbs_val
    t0, _, _, next0 = _read_asn1_tlv(cert_der, pos)
    if t0 == 0xA0:  # [0] EXPLICIT Version
        pos = next0
    # Skip serialNumber, signature, issuer, validity, subject
    for _ in range(5):
        _, _, _, pos = _read_asn1_tlv(cert_der, pos)

    spki_tag, spki_hdr, _, spki_end = _read_asn1_tlv(cert_der, pos)
    if spki_tag != 0x30 or spki_end > tbs_end:
        raise ValueError("Malformed X.509 SubjectPublicKeyInfo")
    return cert_der[spki_hdr:spki_end]


def extract_spki_sha256_b64(cert_der: bytes) -> str:
    """Compute Base64-encoded SHA-256 fingerprint of the X.509 certificate's `SubjectPublicKeyInfo` DER."""
    spki_der = extract_spki_der_from_x509_der(cert_der)
    return base64.b64encode(hashlib.sha256(spki_der).digest()).decode("ascii")


def canonicalize_path_and_query(path: str, raw_query: str = "") -> str:
    """
    Canonical Path + Sorted Query String:
      `path?k1=v1&k2=v2` (sorted lexicographically by `(key, value)`, RFC 3986 percent-encoded)
      or `path` when query is empty.
    """
    if "?" in path:
        base_path, q_in_path = path.split("?", 1)
        eff_query = raw_query if raw_query else q_in_path
    else:
        base_path = path
        eff_query = raw_query
    if not eff_query:
        return base_path
    pairs = urllib.parse.parse_qsl(eff_query, keep_blank_values=True)
    if not pairs:
        return base_path
    sorted_pairs = sorted(pairs, key=lambda kv: (kv[0], kv[1]))
    sorted_qs = urllib.parse.urlencode(sorted_pairs, doseq=True, quote_via=urllib.parse.quote)
    return f"{base_path}?{sorted_qs}"


def compute_hmac_signature_v2(
    sign_secret: str,
    method: str,
    path_with_query: str,
    timestamp: str,
    nonce: str,
    full_raw_body_sha256: str,
) -> str:
    """
    Canonical HMAC-SHA256 v2:
      `METHOD\\npath?sorted_query\\nts\\nnonce\\nsha256(full_raw_http_body)`
    """
    canon_target = canonicalize_path_and_query(path_with_query)
    canonical = f"{method.upper()}\n{canon_target}\n{timestamp}\n{nonce}\n{full_raw_body_sha256.lower()}".encode("utf-8")
    return hmac.new(sign_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def save_credentials(
    endpoint: str | None,
    api_key: str,
    sign_secret: str,
    spki_pin: str | None = None,
) -> Path:
    CRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    ep = (endpoint or DEFAULT_PUBLIC_ENDPOINT).strip().rstrip("/")
    explicit_pins = [p.strip() for p in (spki_pin or "").split(",") if p.strip()]
    payload = {
        "endpoint": ep,
        "api_key": api_key.strip(),
        "sign_secret": sign_secret.strip(),
        "spki_pins": explicit_pins,
        "updated_at": int(time.time()),
    }
    CRED_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(CRED_PATH, 0o600)
    return CRED_PATH


def load_credentials(
    endpoint: str | None = None,
    api_key: str | None = None,
    sign_secret: str | None = None,
    spki_pin: str | None = None,
) -> dict[str, Any]:
    stored: dict[str, Any] = {}
    if CRED_PATH.exists():
        try:
            stored = json.loads(CRED_PATH.read_text(encoding="utf-8"))
        except Exception:
            stored = {}
    stored_ep = str(stored.get("endpoint") or "").rstrip("/")
    is_official_ep = any(
        d in stored_ep.lower() for d in ("atooli.com", "janusflow.cn", "janusflow.net")
    )
    ep = (
        endpoint
        or os.environ.get("JANUSFLOW_ENDPOINT")
        or os.environ.get("CLAW_ENDPOINT")
        or os.environ.get("CLAWNEXUS_ENDPOINT")
        or (stored_ep if is_official_ep else "")
        or DEFAULT_PUBLIC_ENDPOINT
    ).rstrip("/")
    ak = (
        api_key
        or os.environ.get("JANUSFLOW_API_KEY")
        or os.environ.get("CLAW_API_KEY")
        or os.environ.get("CLAWNEXUS_API_KEY")
        or stored.get("api_key")
        or ""
    ).strip()
    sk = (
        sign_secret
        or os.environ.get("JANUSFLOW_SIGN_SECRET")
        or os.environ.get("CLAW_API_SECRET")
        or os.environ.get("CLAW_SIGN_SECRET")
        or os.environ.get("CLAWNEXUS_SIGN_SECRET")
        or stored.get("sign_secret")
        or ""
    ).strip()
    pin_arg = spki_pin or os.environ.get("CLAW_SPKI_PIN") or os.environ.get("CLAWNEXUS_SPKI_PIN") or ""
    if pin_arg.strip():
        pins: tuple[str, ...] | None = tuple(p.strip() for p in pin_arg.split(",") if p.strip())
    elif stored_ep == ep and isinstance(stored.get("spki_pins"), list) and stored["spki_pins"]:
        stored_tuple = tuple(str(p).strip() for p in stored["spki_pins"] if str(p).strip())
        pins = None if (not stored_tuple or set(stored_tuple).issubset(set(DEFAULT_PINNED_SPKI_SHA256))) else stored_tuple
    else:
        pins = None
    return {"endpoint": ep, "api_key": ak, "sign_secret": sk, "spki_pins": pins}


class ClawNexusClient:
    def __init__(
        self,
        endpoint: str = DEFAULT_PUBLIC_ENDPOINT,
        api_key: str = "",
        sign_secret: str = "",
        ca_cert: str | None = None,
        spki_pins: tuple[str, ...] | list[str] | None = None,
        pin_mode: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        self.endpoint = (endpoint or DEFAULT_PUBLIC_ENDPOINT).rstrip("/")
        self.api_key = api_key
        self.sign_secret = sign_secret
        self.ca_cert = ca_cert
        self._explicit_spki_pins = spki_pins is not None
        self.spki_pins: tuple[str, ...] = (
            tuple(spki_pins) if spki_pins is not None else DEFAULT_PINNED_SPKI_SHA256
        )
        self.timeout = timeout
        parsed = urllib.parse.urlparse(self.endpoint)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        raw_mode = (pin_mode or os.environ.get("CLAWNEXUS_PIN_MODE") or "").strip().lower()
        if raw_mode in ("strict", "ca", "off"):
            self.pin_mode = raw_mode
        else:
            self.pin_mode = "strict"
        self.last_peer_spki_sha256: str = ""
        self.last_spki_pin_matched: bool = False

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if getattr(ssl, "HAS_TLSv1_3", False):
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            except ValueError:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        try:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
        except Exception:
            pass
        ctx.load_verify_locations(cadata=EMBEDDED_PUBLIC_CA_CHAIN_PEM)
        if self.ca_cert:
            ctx.load_verify_locations(cafile=self.ca_cert)
        return ctx

    def _verify_peer_spki_pin(self, tls_sock: ssl.SSLSocket) -> None:
        peer_der = tls_sock.getpeercert(binary_form=True)
        if not peer_der:
            raise SPKIPinMismatchError("Peer did not present an X.509 certificate during TLS 1.3 handshake")
        actual_pin = extract_spki_sha256_b64(peer_der)
        self.last_peer_spki_sha256 = actual_pin

        candidate_pins = [actual_pin]
        if hasattr(tls_sock, "get_verified_chain"):
            try:
                for c_der in tls_sock.get_verified_chain() or []:
                    if isinstance(c_der, (bytes, bytearray)):
                        candidate_pins.append(extract_spki_sha256_b64(bytes(c_der)))
            except Exception:
                pass

        matched = any(
            hmac.compare_digest(cp, exp)
            for cp in candidate_pins
            for exp in self.spki_pins
        )
        self.last_spki_pin_matched = matched
        if self.pin_mode == "off" or not self.spki_pins:
            return
        if self.pin_mode == "strict" and not matched:
            raise SPKIPinMismatchError(
                f"TLS 1.3 SPKI pin verification failed: peer SPKI sha256={actual_pin} not in pinned set {self.spki_pins}"
            )

    def request_raw(
        self,
        method: str,
        path_with_query: str,
        body: bytes = b"",
        content_type: str = "",
        require_auth: bool = True,
        retries: int = 2,
    ) -> tuple[int, dict[str, str], bytes]:
        full_body_sha = hashlib.sha256(body).hexdigest().lower()

        last_err: Exception | None = None
        default_port = (self.scheme == "https" and self.port == 443) or (self.scheme == "http" and self.port == 80)
        host_hdr = self.host if default_port else f"{self.host}:{self.port}"
        for attempt in range(retries + 1):
            headers: dict[str, str] = {"Host": host_hdr}
            if content_type:
                headers["Content-Type"] = content_type
            if method.upper() == "POST":
                headers["Content-Length"] = str(len(body))
            if require_auth:
                if not self.api_key or not self.sign_secret:
                    raise ValueError("Missing API key or sign_secret; run `janusflow-probe auth login` or set JANUSFLOW_API_KEY & JANUSFLOW_SIGN_SECRET")
                ts = str(int(time.time()))
                nonce = secrets.token_hex(12)
                sig = compute_hmac_signature_v2(
                    self.sign_secret,
                    method,
                    path_with_query,
                    ts,
                    nonce,
                    full_body_sha,
                )
                headers.update(
                    {
                        "X-API-Key": self.api_key,
                        "X-Claw-Sig-Version": "v2",
                        "X-Claw-Timestamp": ts,
                        "X-Claw-Nonce": nonce,
                        "X-Claw-Signature": sig,
                        "X-Claw-Body-SHA256": full_body_sha,
                    }
                )

            sock: socket.socket | ssl.SSLSocket | None = None
            try:
                raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.scheme == "https":
                    tls_sock = self._ssl_context().wrap_socket(raw_sock, server_hostname=self.host)
                    self._verify_peer_spki_pin(tls_sock)
                    sock = tls_sock
                else:
                    sock = raw_sock
                req_head = (
                    f"{method.upper()} {path_with_query} HTTP/1.1\r\n"
                    + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
                    + "\r\nConnection: close\r\n\r\n"
                ).encode("latin-1")
                sock.sendall(req_head)
                if body:
                    try:
                        chunk_sz = 524288
                        for off in range(0, len(body), chunk_sz):
                            sock.sendall(body[off : off + chunk_sz])
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                resp = http.client.HTTPResponse(sock)
                resp.begin()
                resp_bytes = resp.read()
                resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.status
                sock.close()
                if status in (502, 504) and attempt < retries:
                    time.sleep(0.4 * (attempt + 1))
                    continue
                return status, resp_hdrs, resp_bytes
            except ssl.SSLError:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                raise
            except (socket.timeout, ConnectionError, OSError) as exc:
                last_err = exc
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                if attempt < retries:
                    time.sleep(0.4 * (attempt + 1))
                    continue
                raise
        raise RuntimeError(f"Request failed after retries: {last_err}")

    def request_json(
        self,
        method: str,
        path_with_query: str,
        payload: dict[str, Any] | None = None,
        require_auth: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else b""
        ctype = "application/json; charset=utf-8" if payload is not None else ""
        st, _, raw = self.request_raw(method, path_with_query, body=body, content_type=ctype, require_auth=require_auth)
        try:
            return st, json.loads(raw.decode("utf-8"))
        except Exception:
            return st, {"raw_text": raw.decode("utf-8", errors="replace")}

    def upload_multipart(
        self,
        path_with_query: str,
        file_path: Path | None,
        fields: dict[str, str],
        log_fn: Any = None,
    ) -> tuple[int, dict[str, Any]]:
        effective_fields = dict(fields)
        file_bytes = b""
        use_instant_dedup = False

        if file_path is not None:
            file_bytes = file_path.read_bytes()
            apk_sha = hashlib.sha256(file_bytes).hexdigest()
            is_conf = str(effective_fields.get("confidential") or "false").strip().lower() in ("true", "1", "yes")
            if not is_conf and path_with_query == "/api/v1/inspect/submit":
                try:
                    p_st, p_res = self.request_json(
                        "POST",
                        "/api/v1/public/quick-scan",
                        payload={
                            "apk_sha256": apk_sha,
                            "apk_size": len(file_bytes),
                            "filename": file_path.name,
                            "probe_only": True,
                        },
                        require_auth=False,
                    )
                    if p_st == 200 and isinstance(p_res, dict) and p_res.get("cas_exists"):
                        use_instant_dedup = True
                        effective_fields["apk_sha256"] = apk_sha
                        effective_fields["filename"] = file_path.name
                        if log_fn:
                            mb_saved = round(len(file_bytes) / (1024 * 1024), 2)
                            log_fn(f"⚡ 命中服务端 SHA-256 极速秒传！已免除 {mb_saved} MB 重复上传，0 字节秒级直达沙箱...")
                except Exception:
                    pass

        boundary = f"----ClawNexusCLIBoundary{secrets.token_hex(12)}"
        parts: list[bytes] = []
        for k, v in effective_fields.items():
            parts.append(f"--{boundary}\r\n".encode("utf-8"))
            parts.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode("utf-8"))
        if file_path is not None and not use_instant_dedup:
            parts.append(f"--{boundary}\r\n".encode("utf-8"))
            parts.append(
                f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n".encode("utf-8")
            )
            parts.append(file_bytes)
            parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        else:
            parts.append(f"--{boundary}--\r\n".encode("utf-8"))
        multipart_body = b"".join(parts)

        st, _, raw = self.request_raw(
            "POST",
            path_with_query,
            body=multipart_body,
            content_type=f"multipart/form-data; boundary={boundary}",
            require_auth=True,
        )
        try:
            return st, json.loads(raw.decode("utf-8"))
        except Exception:
            return st, {"raw_text": raw.decode("utf-8", errors="replace")}


JanusFlowClient = ClawNexusClient
ClawProbeClient = ClawNexusClient
