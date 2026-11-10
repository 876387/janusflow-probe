#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JanusFlow (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com) — FlowSketch v2 (`2.0-pa`)
Zero-Dependency Local Pre-Extractor, Adaptive TCP MSS Normalizer & Dual-Tower Stream Parser.

Designed for two primary probe architectures:
  1. Edge OpenWrt / Linux Enterprise Gateways (`probes/openwrt_edge/`):
     Converts 60s ring-buffer captures (`snaplen=256`) in local RAM into compact `.fsk.jsonl.gz`
     sketches (50x~150x compression), keeping raw encrypted bulk payloads inside the local LAN.
  2. Core Network 10G/40G Optical TAP / Switch SPAN Mirror Probes (`probes/core_10g_tap/`):
     Strips 802.1Q VLAN / 802.1ad QinQ / VXLAN encapsulation, validates `ethtool -k` hardware
     offload lockdown (`tso/gso/gro=off`), and performs single-pass per-flow adaptive TCP MSS
     estimation (`est_mss`) to fold any residual hypervisor/NIC super-frames (`>1500B`) into
     true wire-equivalent packet length sequences for the JanusFlow Sequence Tower (Track A)
     and Byte Tower (Track B).

Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import ipaddress
import json
import socket
import struct
import time
from collections import Counter
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple

FSK_SCHEMA_VERSION_V2_PA = "2.0-pa"

SKIP_PORTS = frozenset({22, 5555, 5037, 5353, 1900})
WELL_KNOWN_SERVER_PORTS = frozenset({80, 443, 8080, 8443, 5222, 5223, 5228, 8000, 9443})
MAX_SEQ_LEN = 64
MAX_PAY_PKTS = 5
MAX_PAY_HEX_BYTES = 128
UPLINK_CHUNK_MIN_B = 1150
UPLINK_CHUNK_MAX_B = 1500
DOWNLINK_ACK_MIN_B = 20
DOWNLINK_ACK_MAX_B = 160

STANDARD_ETHERNET_MTU = 1500
MIN_VALID_TCP_MSS = 536
MAX_ETHERNET_TCP_MSS = 1460
DEFAULT_FALLBACK_MSS_IPV4 = 1460
DEFAULT_FALLBACK_MSS_IPV6 = 1440

REQUIRED_OFFLOAD_KEYS = (
    "tcp-segmentation-offload",
    "generic-segmentation-offload",
    "generic-receive-offload",
)


def verify_ethtool_offloads_disabled(ethtool_k_input: str | Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Validate `ethtool -k <iface>` text or parsed dict for 10G Optical TAP / SPAN probes:
    Asserts `tcp-segmentation-offload`, `generic-segmentation-offload`, and
    `generic-receive-offload` are explicitly set to `off`.
    """
    if ethtool_k_input is None:
        return {
            "offload_state": "UNKNOWN",
            "compliant": False,
            "features": {},
            "missing_or_enabled": list(REQUIRED_OFFLOAD_KEYS),
        }

    parsed: Dict[str, str] = {}
    if isinstance(ethtool_k_input, dict):
        for raw_k, raw_v in ethtool_k_input.items():
            k_norm = str(raw_k).strip().rstrip(":").lower()
            if k_norm in REQUIRED_OFFLOAD_KEYS:
                v_str = str(raw_v).strip()
                parsed[k_norm] = v_str.split()[0].lower() if v_str else ""
    elif isinstance(ethtool_k_input, str):
        if not ethtool_k_input.strip():
            return {
                "offload_state": "UNKNOWN",
                "compliant": False,
                "features": {},
                "missing_or_enabled": list(REQUIRED_OFFLOAD_KEYS),
            }
        for raw_ln in ethtool_k_input.splitlines():
            ln = raw_ln.strip()
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            k_norm = k.strip().lower()
            if k_norm in REQUIRED_OFFLOAD_KEYS:
                val_token = v.strip().split()[0].lower() if v.strip() else ""
                parsed[k_norm] = val_token

    if not parsed:
        return {
            "offload_state": "UNKNOWN",
            "compliant": False,
            "features": {},
            "missing_or_enabled": list(REQUIRED_OFFLOAD_KEYS),
        }

    bad = [k for k in REQUIRED_OFFLOAD_KEYS if parsed.get(k) != "off"]
    compliant = len(bad) == 0
    return {
        "offload_state": "VERIFIED_OFF" if compliant else "ACTIVE_OR_PARTIAL",
        "compliant": compliant,
        "features": parsed,
        "missing_or_enabled": bad,
    }


def _is_private_ip_str(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return bool(addr.is_private or addr.is_link_local)
    except ValueError:
        return False


def _is_ignored_ip_str(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return bool(addr.is_loopback or addr.is_multicast or addr.is_unspecified) or ip_str == "255.255.255.255"
    except ValueError:
        return True


def parse_tls_client_hello_sni_alpn(buf: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Pure stdlib TLS Record + ClientHello parser returning `(sni, alpn)`."""
    try:
        hs = bytearray()
        p = 0
        blen = len(buf)
        while p + 5 <= blen and buf[p] == 0x16:
            rec_len = struct.unpack_from("!H", buf, p + 3)[0]
            hs.extend(buf[p + 5 : min(blen, p + 5 + rec_len)])
            p += 5 + rec_len
            if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
                break
        if len(hs) < 42 or hs[0] != 0x01:
            return None, None
        msg_len = int.from_bytes(hs[1:4], "big")
        body = memoryview(hs)[4 : min(len(hs), 4 + msg_len)]
        q = 34  # client_version (2) + random (32)
        if q >= len(body):
            return None, None
        sid_len = body[q]
        q += 1 + sid_len
        if q + 2 > len(body):
            return None, None
        cs_len = struct.unpack_from("!H", body, q)[0]
        q += 2 + cs_len
        if q >= len(body):
            return None, None
        comp_len = body[q]
        q += 1 + comp_len
        if q + 2 > len(body):
            return None, None
        ext_total = struct.unpack_from("!H", body, q)[0]
        q += 2
        end = min(len(body), q + ext_total)
        sni: Optional[str] = None
        alpn: Optional[str] = None
        while q + 4 <= end:
            etype, elen = struct.unpack_from("!HH", body, q)
            q += 4
            edata = bytes(body[q : min(end, q + elen)])
            q += elen
            if etype == 0 and len(edata) > 5:
                name_len = struct.unpack_from("!H", edata, 3)[0]
                raw_sni = edata[5 : 5 + name_len].decode("ascii", "ignore").strip().lower()
                if "." in raw_sni:
                    sni = raw_sni
            elif etype == 16 and len(edata) > 2:
                protos: List[str] = []
                k = 2
                while k < len(edata):
                    plen = edata[k]
                    if plen == 0 or k + 1 + plen > len(edata):
                        break
                    protos.append(edata[k + 1 : k + 1 + plen].decode("ascii", "ignore"))
                    k += 1 + plen
                if protos:
                    alpn = ",".join(protos)
        return sni, alpn
    except Exception:
        return None, None


def parse_http_host_header(buf: bytes) -> Optional[str]:
    """Extract plaintext HTTP/1.x Host header if payload begins with an HTTP request verb."""
    if len(buf) < 16:
        return None
    if not buf.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"OPTIONS ")):
        return None
    try:
        head_txt = buf[:1024].decode("latin-1", errors="ignore")
        for line in head_txt.split("\r\n")[1:16]:
            if line.lower().startswith("host:"):
                host_val = line.split(":", 1)[1].strip().lower()
                if ":" in host_val and not host_val.startswith("["):
                    host_val = host_val.split(":", 1)[0]
                if "." in host_val and not host_val.replace(".", "").isdigit():
                    return host_val
    except Exception:
        return None
    return None


def _read_dns_name(msg: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    pos = offset
    jumped = False
    next_pos = offset
    hops = 0
    mlen = len(msg)
    while pos < mlen and hops < 24:
        hops += 1
        ln = msg[pos]
        if ln == 0:
            if not jumped:
                next_pos = pos + 1
            break
        if (ln & 0xC0) == 0xC0:
            if pos + 1 >= mlen:
                return "", mlen
            ptr = ((ln & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                next_pos = pos + 2
                jumped = True
            pos = ptr
            continue
        pos += 1
        if pos + ln > mlen:
            return "", mlen
        labels.append(msg[pos : pos + ln].decode("ascii", "ignore").lower())
        pos += ln
    return ".".join(p for p in labels if p), (next_pos if jumped else max(next_pos, pos + 1))


def parse_dns_response_records(payload: bytes, out_map: Dict[str, str]) -> None:
    """Pure stdlib DNS response parser extracting A (1) and AAAA (28) IP -> qname mappings."""
    if len(payload) < 12:
        return
    try:
        _txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from("!HHHHHH", payload, 0)
        if (flags & 0x8000) == 0 or qdcount == 0 or ancount == 0:
            return
        pos = 12
        qname = ""
        for i in range(min(qdcount, 4)):
            qn, pos = _read_dns_name(payload, pos)
            if i == 0:
                qname = qn.rstrip(".")
            if pos + 4 > len(payload):
                return
            pos += 4
        if not qname or "." not in qname:
            return
        for _ in range(min(ancount, 32)):
            if pos >= len(payload):
                break
            _aname, pos = _read_dns_name(payload, pos)
            if pos + 10 > len(payload):
                break
            rtype, rclass, _ttl, rdlen = struct.unpack_from("!HHIH", payload, pos)
            pos += 10
            if pos + rdlen > len(payload):
                break
            rdata = payload[pos : pos + rdlen]
            pos += rdlen
            if rclass == 1 and rtype == 1 and rdlen == 4:
                out_map[socket.inet_ntoa(rdata)] = qname
            elif rclass == 1 and rtype == 28 and rdlen == 16:
                out_map[socket.inet_ntop(socket.AF_INET6, rdata)] = qname
    except Exception:
        return


def _extract_ip_from_frame(
    frame: bytes,
    linktype: int,
    orig_len: int,
) -> Tuple[Optional[bytes], Optional[int], int]:
    """
    Return `(ip_packet_bytes, sll_direction, ip_orig_wire_len)` across Ethernet (with 802.1Q VLAN,
    802.1ad QinQ, and PPPoE Session decapsulation for 10G optical TAPs & OpenWrt WAN links),
    Linux SLL/SLL2, and Raw IP.
    """
    flen = len(frame)
    eff_orig = max(flen, orig_len)
    if linktype == 1:  # DLT_EN10MB (Ethernet)
        if flen < 14:
            return None, None, 0
        eth_type = struct.unpack_from("!H", frame, 12)[0]
        off = 14
        # Strip up to two VLAN tags (802.1Q 0x8100 / 802.1ad QinQ 0x88A8 / 0x9100)
        for _ in range(2):
            if eth_type in (0x8100, 0x88A8, 0x9100) and flen >= off + 4:
                eth_type = struct.unpack_from("!H", frame, off + 2)[0]
                off += 4
            else:
                break
        # Strip PPPoE Session header (0x8864) common on OpenWrt PPPoE WAN interfaces
        if eth_type == 0x8864 and flen >= off + 8:
            ppp_proto = struct.unpack_from("!H", frame, off + 6)[0]
            if ppp_proto in (0x0021, 0x0057):
                off += 8
                ip_b = frame[off:]
                return ip_b, None, max(len(ip_b), eff_orig - off)
        if eth_type in (0x0800, 0x86DD):
            ip_b = frame[off:]
            return ip_b, None, max(len(ip_b), eff_orig - off)
        return None, None, 0
    if linktype == 113:  # DLT_LINUX_SLL
        if flen < 16:
            return None, None, 0
        pkt_type = struct.unpack_from("!H", frame, 0)[0]
        proto = struct.unpack_from("!H", frame, 14)[0]
        if proto in (0x0800, 0x86DD):
            ip_b = frame[16:]
            return ip_b, pkt_type, max(len(ip_b), eff_orig - 16)
        return None, None, 0
    if linktype == 276:  # DLT_LINUX_SLL2
        if flen < 20:
            return None, None, 0
        proto = struct.unpack_from("!H", frame, 0)[0]
        pkt_type = frame[10]
        if proto in (0x0800, 0x86DD):
            ip_b = frame[20:]
            return ip_b, pkt_type, max(len(ip_b), eff_orig - 20)
        return None, None, 0
    if linktype in (101, 12, 228, 14):  # Raw IP
        return (frame, None, eff_orig) if flen >= 20 else (None, None, 0)
    return None, None, 0


def _iter_pcap_packets_from_stream(stream: BinaryIO, first4: bytes) -> Iterator[Tuple[float, int, bytes, int]]:
    """Yield `(timestamp_sec, linktype, raw_frame_bytes, orig_wire_len)` from PCAP or PCAPNG stream."""
    if first4 in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if first4 in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        ns_scale = 1e-9 if first4 in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
        rest_hdr = stream.read(20)
        if len(rest_hdr) < 20:
            return
        _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(f"{endian}HHiiii", rest_hdr)
        linktype = linktype & 0xFFFF
        pkt_hdr_struct = struct.Struct(f"{endian}IIII")
        while True:
            ph = stream.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_sub, incl_len, orig_len = pkt_hdr_struct.unpack(ph)
            if incl_len > 262144:
                break
            frame = stream.read(incl_len)
            if len(frame) < incl_len:
                break
            yield float(ts_sec) + float(ts_sub) * ns_scale, linktype, frame, max(incl_len, orig_len)
        return

    if first4 == b"\x0a\x0d\x0d\x0a":
        rest8 = stream.read(8)
        if len(rest8) < 8:
            return
        bom = rest8[4:8]
        endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        shb_len = struct.unpack(f"{endian}I", rest8[0:4])[0]
        if shb_len >= 12:
            stream.read(shb_len - 12)
        if_linktypes: List[int] = []
        if_tsresol: List[float] = []
        hdr_u32_2 = struct.Struct(f"{endian}II")
        while True:
            bh = stream.read(8)
            if len(bh) < 8:
                break
            btype, blen = hdr_u32_2.unpack(bh)
            if blen < 12 or blen > 1048576:
                break
            body = stream.read(blen - 8)
            if len(body) < blen - 8:
                break
            payload = body[:-4]
            if btype == 0x0A0D0D0A and len(payload) >= 4:
                bom2 = payload[0:4]
                endian = "<" if bom2 == b"\x4d\x3c\x2b\x1a" else ">"
                hdr_u32_2 = struct.Struct(f"{endian}II")
                if_linktypes.clear()
                if_tsresol.clear()
            elif btype == 0x00000001 and len(payload) >= 8:  # IDB
                lt = struct.unpack_from(f"{endian}H", payload, 0)[0]
                if_linktypes.append(lt)
                if_tsresol.append(1e-6)
            elif btype == 0x00000006 and len(payload) >= 20:  # EPB
                if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(f"{endian}IIIII", payload, 0)
                lt = if_linktypes[if_id] if if_id < len(if_linktypes) else 1
                scale = if_tsresol[if_id] if if_id < len(if_tsresol) else 1e-6
                ts = ((ts_hi << 32) | ts_lo) * scale
                yield ts, lt, payload[20 : 20 + cap_len], max(cap_len, orig_len)
            elif btype == 0x00000003 and len(payload) >= 4:  # SPB
                lt = if_linktypes[0] if if_linktypes else 1
                orig_l = struct.unpack_from(f"{endian}I", payload, 0)[0]
                raw_f = payload[4:]
                yield 0.0, lt, raw_f, max(len(raw_f), orig_l)


def _decode_l3_l4(
    ip_buf: bytes,
    ip_orig_wire: int,
) -> Optional[Tuple[str, str, int, int, str, int, bytes, int, int, bool]]:
    """
    Decode IPv4/IPv6 + TCP/UDP (with automatic VXLAN UDP 4789 inner packet unwrap for 10G core taps).
    """
    blen = len(ip_buf)
    if blen < 20:
        return None
    ver = ip_buf[0] >> 4
    if ver == 4:
        ihl = (ip_buf[0] & 0x0F) * 4
        if ihl < 20 or blen < ihl + 8:
            return None
        total_len = struct.unpack_from("!H", ip_buf, 2)[0]
        eff_ip_total = total_len if total_len >= ihl else max(blen, ip_orig_wire)
        proto_num = ip_buf[9]
        src_ip = socket.inet_ntoa(ip_buf[12:16])
        dst_ip = socket.inet_ntoa(ip_buf[16:20])
        l4_off = ihl
        ip_payload_wire = max(blen - ihl, eff_ip_total - ihl)
    elif ver == 6:
        if blen < 48:
            return None
        plen = struct.unpack_from("!H", ip_buf, 4)[0]
        proto_num = ip_buf[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_buf[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_buf[24:40])
        l4_off = 40
        ip_payload_wire = max(blen - 40, plen if plen > 0 else max(0, ip_orig_wire - 40))
    else:
        return None

    if proto_num == 6:  # TCP
        if blen < l4_off + 14:
            return None
        sp, dp = struct.unpack_from("!HH", ip_buf, l4_off)
        tcp_hdr_len = ((ip_buf[l4_off + 12] >> 4) & 0x0F) * 4
        if tcp_hdr_len < 20:
            return None
        tcp_hdr_complete = blen >= l4_off + tcp_hdr_len
        cap_pl = ip_buf[l4_off + tcp_hdr_len :] if tcp_hdr_complete else b""
        wire_pl_len = max(len(cap_pl), ip_payload_wire - tcp_hdr_len)
        return src_ip, dst_ip, sp, dp, "tcp", max(0, wire_pl_len), cap_pl, l4_off, tcp_hdr_len, tcp_hdr_complete

    if proto_num == 17:  # UDP
        sp, dp, udp_len = struct.unpack_from("!HHH", ip_buf, l4_off)[:3]
        cap_pl = ip_buf[l4_off + 8 :] if blen > l4_off + 8 else b""
        wire_pl_len = max(len(cap_pl), (udp_len - 8) if udp_len >= 8 else (ip_payload_wire - 8))
        # Automatic VXLAN (UDP dst 4789) inner Ethernet frame decapsulation for core network ERSPAN/VXLAN mirrors
        if dp == 4789 and len(cap_pl) >= 8 + 14 + 20 and (cap_pl[0] & 0x08) != 0:
            inner_ip, _, inner_orig = _extract_ip_from_frame(cap_pl[8:], 1, max(len(cap_pl) - 8, wire_pl_len - 8))
            if inner_ip is not None:
                inner_dec = _decode_l3_l4(inner_ip, inner_orig)
                if inner_dec is not None:
                    return inner_dec
        return src_ip, dst_ip, sp, dp, "udp", max(0, wire_pl_len), cap_pl, l4_off, 8, True

    return None


class _ChainedStream(io.RawIOBase):
    def __init__(self, prefix: bytes, underlying: BinaryIO) -> None:
        self._prefix = prefix
        self._pos = 0
        self._underlying = underlying

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        if self._pos < len(self._prefix):
            if size < 0:
                rem = self._prefix[self._pos :]
                self._pos = len(self._prefix)
                return rem + self._underlying.read()
            take = self._prefix[self._pos : self._pos + size]
            self._pos += len(take)
            if len(take) == size:
                return take
            return take + self._underlying.read(size - len(take))
        return self._underlying.read(size)


def _fold_oversized_tcp_counter(
    oversized_counts: Counter[Tuple[int, int]],
    est_mss: int,
) -> Tuple[int, int, int, int, int]:
    """
    Fold compact `(hdr_len, wire_len) -> count` histogram of `ip_wire_total > 1500` TCP frames
    using finalized `est_mss` (`FlowSketch v2 2.0-pa` normalization).
    """
    split_raw_pkts = 0
    split_equiv_segs = 0
    delta_pkts = 0
    delta_chunk_pkts = 0
    delta_ack_pkts = 0

    for (hdr_len, wire_len), cnt in oversized_counts.items():
        eff_mss = est_mss if wire_len > est_mss else max(MIN_VALID_TCP_MSS, STANDARD_ETHERNET_MTU - hdr_len)
        if wire_len <= eff_mss:
            continue

        raw_was_chunk = 1 if (UPLINK_CHUNK_MIN_B <= wire_len <= UPLINK_CHUNK_MAX_B) else 0
        raw_was_ack = 1 if (DOWNLINK_ACK_MIN_B <= wire_len <= DOWNLINK_ACK_MAX_B) else 0

        full_segs = wire_len // eff_mss
        rem = wire_len % eff_mss
        equiv_pkts = full_segs + (1 if rem > 0 else 0)
        equiv_chunk = (full_segs if (UPLINK_CHUNK_MIN_B <= eff_mss <= UPLINK_CHUNK_MAX_B) else 0) + (
            1 if (UPLINK_CHUNK_MIN_B <= rem <= UPLINK_CHUNK_MAX_B) else 0
        )
        equiv_ack = (full_segs if (DOWNLINK_ACK_MIN_B <= eff_mss <= DOWNLINK_ACK_MAX_B) else 0) + (
            1 if (DOWNLINK_ACK_MIN_B <= rem <= DOWNLINK_ACK_MAX_B) else 0
        )

        split_raw_pkts += cnt
        split_equiv_segs += cnt * equiv_pkts
        delta_pkts += cnt * (equiv_pkts - 1)
        delta_chunk_pkts += cnt * (equiv_chunk - raw_was_chunk)
        delta_ack_pkts += cnt * (equiv_ack - raw_was_ack)

    return split_raw_pkts, split_equiv_segs, delta_pkts, delta_chunk_pkts, delta_ack_pkts


def parse_flowsketch_jsonl_text(text_data: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for line in text_data.splitlines():
        ln = line.strip()
        if not ln:
            continue
        try:
            r = json.loads(ln)
        except Exception:
            continue
        seq_raw = r.get("seq") or []
        if not seq_raw:
            continue
        srv = str(r.get("server") or "0.0.0.0:443")
        sip = str(r.get("sip") or "")
        sport = int(r.get("sport") or r.get("dst_port") or 0)
        if not sip:
            if srv.startswith("[") and "]:" in srv:
                sip, p_s = srv[1:].split("]:", 1)
                sport = sport or int(p_s)
            elif ":" in srv:
                sip, p_s = srv.rsplit(":", 1)
                try:
                    sport = sport or int(p_s)
                except ValueError:
                    sport = sport or 443
            else:
                sip = srv
        records.append(
            {
                "fsk_version": r.get("fsk_version") or FSK_SCHEMA_VERSION_V2_PA,
                "client": str(r.get("client") or "0.0.0.0"),
                "cport": int(r.get("cport") or 0),
                "sip": sip,
                "sport": sport,
                "server": srv,
                "dst_port": sport,
                "proto": str(r.get("proto") or "udp").lower(),
                "t0": float(r.get("t0") or 0.0),
                "t_end": float(r.get("t_end") or r.get("t0") or 0.0),
                "seq": [str(x) for x in seq_raw[:MAX_SEQ_LEN]],
                "pay": [str(x) for x in (r.get("pay") or [])[:MAX_PAY_PKTS]],
                "sni": r.get("sni"),
                "alpn": r.get("alpn"),
                "dns": r.get("dns"),
                "wire_up_bytes": r.get("wire_up_bytes"),
                "wire_down_bytes": r.get("wire_down_bytes"),
                "wire_up_pkts": r.get("wire_up_pkts"),
                "wire_down_pkts": r.get("wire_down_pkts"),
                "wire_up_chunk_pkts": r.get("wire_up_chunk_pkts"),
                "wire_down_ack_pkts": r.get("wire_down_ack_pkts"),
                "wire_down_chunk_pkts": r.get("wire_down_chunk_pkts"),
                "wire_up_ack_pkts": r.get("wire_up_ack_pkts"),
                "est_mss": r.get("est_mss"),
                "oversized_up_pkts": int(r.get("oversized_up_pkts") or 0),
                "oversized_down_pkts": int(r.get("oversized_down_pkts") or 0),
                "oversized_up_equiv_segs": int(r.get("oversized_up_equiv_segs") or 0),
                "oversized_down_equiv_segs": int(r.get("oversized_down_equiv_segs") or 0),
                "raw_wire_up_pkts": r.get("raw_wire_up_pkts"),
                "raw_wire_up_chunk_pkts": r.get("raw_wire_up_chunk_pkts"),
                "raw_wire_down_pkts": r.get("raw_wire_down_pkts"),
                "raw_wire_down_ack_pkts": r.get("raw_wire_down_ack_pkts"),
            }
        )
    return records


def _parse_decompressed_stream(stream: BinaryIO) -> List[Dict[str, Any]]:
    first4 = stream.read(4)
    if len(first4) < 4:
        return []

    if first4 not in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    ):
        text_data = (first4 + stream.read()).decode("utf-8", errors="ignore")
        return parse_flowsketch_jsonl_text(text_data)

    streams: Dict[Tuple[str, str, int, int, str], Dict[str, Any]] = {}
    archived: List[Dict[str, Any]] = []
    dns_ip_to_domain: Dict[str, str] = {}
    bidir_tcp_max_non_jumbo: Dict[Tuple[Tuple[str, int], Tuple[str, int]], int] = {}

    for ts, linktype, frame, orig_len in _iter_pcap_packets_from_stream(stream, first4):
        ip_buf, sll_dir, ip_orig_wire = _extract_ip_from_frame(frame, linktype, orig_len)
        if not ip_buf:
            continue
        decoded = _decode_l3_l4(ip_buf, ip_orig_wire)
        if not decoded:
            continue
        src, dst, sp, dp, proto, wire_len, pl, l3_hdr_len, l4_hdr_len, tcp_hdr_complete = decoded

        ep_src, ep_dst = (src, sp), (dst, dp)
        ep_lo, ep_hi = (ep_src, ep_dst) if ep_src <= ep_dst else (ep_dst, ep_src)
        bidir_key: Optional[Tuple[Tuple[str, int], Tuple[str, int]]] = None
        hdr_total_len = l3_hdr_len + l4_hdr_len
        ip_wire_total = hdr_total_len + wire_len
        if proto == "tcp" and tcp_hdr_complete:
            bidir_key = (ep_lo, ep_hi)
            if ip_wire_total <= STANDARD_ETHERNET_MTU and MIN_VALID_TCP_MSS <= wire_len <= MAX_ETHERNET_TCP_MSS:
                prev_mss = bidir_tcp_max_non_jumbo.get(bidir_key, 0)
                if wire_len > prev_mss:
                    bidir_tcp_max_non_jumbo[bidir_key] = wire_len

        if sp in SKIP_PORTS or dp in SKIP_PORTS:
            continue
        if _is_ignored_ip_str(src) or _is_ignored_ip_str(dst):
            continue

        if proto == "udp" and (sp == 53 or dp == 53):
            if pl:
                parse_dns_response_records(pl, dns_ip_to_domain)
            continue

        src_priv, dst_priv = _is_private_ip_str(src), _is_private_ip_str(dst)
        if sll_dir == 4:
            is_up = True
        elif sll_dir == 0:
            is_up = False
        elif src_priv and not dst_priv:
            is_up = True
        elif dst_priv and not src_priv:
            is_up = False
        elif dp in WELL_KNOWN_SERVER_PORTS and sp not in WELL_KNOWN_SERVER_PORTS:
            is_up = True
        elif sp in WELL_KNOWN_SERVER_PORTS and dp not in WELL_KNOWN_SERVER_PORTS:
            is_up = False
        else:
            is_up = sp >= dp

        c_ip, s_ip, c_port, s_port = (src, dst, sp, dp) if is_up else (dst, src, dp, sp)
        fkey = (c_ip, s_ip, c_port, s_port, proto)
        st = streams.get(fkey)
        if st is not None and len(st["seq"]) >= 2 and ts > 0 and (
            (ts - st["t_end"]) >= 3.2 or ((ts - st["t0"]) >= 7.8 and len(st["seq"]) >= 12)
        ):
            archived.append(st)
            st = None

        if st is None:
            if proto == "tcp" and bidir_key is None:
                ep_a, ep_b = (c_ip, c_port), (s_ip, s_port)
                bidir_key = (ep_a, ep_b) if ep_a <= ep_b else (ep_b, ep_a)
            st = {
                "client": c_ip,
                "cport": c_port,
                "sip": s_ip,
                "sport": s_port,
                "server": f"[{s_ip}]:{s_port}" if ":" in s_ip else f"{s_ip}:{s_port}",
                "dst_port": s_port,
                "proto": proto,
                "bidir_key": bidir_key,
                "t0": float(ts),
                "t_end": float(ts),
                "seq": [],
                "seq_oversized_meta": [],
                "pay": [],
                "cbuf": bytearray(),
                "http_host": None,
                "wire_up_bytes": 0,
                "wire_down_bytes": 0,
                "raw_wire_up_pkts": 0,
                "raw_wire_down_pkts": 0,
                "raw_wire_up_chunk_pkts": 0,
                "raw_wire_down_ack_pkts": 0,
                "raw_wire_down_chunk_pkts": 0,
                "raw_wire_up_ack_pkts": 0,
                "oversized_up_hist": Counter(),
                "oversized_down_hist": Counter(),
            }
            streams[fkey] = st

        if ts > 0:
            st["t_end"] = float(ts)

        if wire_len > 0:
            is_oversized_tcp_candidate = (
                proto == "tcp" and tcp_hdr_complete and ip_wire_total > STANDARD_ETHERNET_MTU
            )
            if is_up:
                st["wire_up_bytes"] += wire_len
                st["raw_wire_up_pkts"] += 1
                if UPLINK_CHUNK_MIN_B <= wire_len <= UPLINK_CHUNK_MAX_B:
                    st["raw_wire_up_chunk_pkts"] += 1
                if DOWNLINK_ACK_MIN_B <= wire_len <= DOWNLINK_ACK_MAX_B:
                    st["raw_wire_up_ack_pkts"] += 1
                if is_oversized_tcp_candidate:
                    st["oversized_up_hist"][(hdr_total_len, wire_len)] += 1
            else:
                st["wire_down_bytes"] += wire_len
                st["raw_wire_down_pkts"] += 1
                if DOWNLINK_ACK_MIN_B <= wire_len <= DOWNLINK_ACK_MAX_B:
                    st["raw_wire_down_ack_pkts"] += 1
                if UPLINK_CHUNK_MIN_B <= wire_len <= UPLINK_CHUNK_MAX_B:
                    st["raw_wire_down_chunk_pkts"] += 1
                if is_oversized_tcp_candidate:
                    st["oversized_down_hist"][(hdr_total_len, wire_len)] += 1

            sign_char = "+" if is_up else "-"
            if len(st["seq"]) < MAX_SEQ_LEN:
                seq_idx = len(st["seq"])
                st["seq"].append(f"{sign_char}{wire_len}")
                if is_oversized_tcp_candidate:
                    st["seq_oversized_meta"].append((seq_idx, sign_char, hdr_total_len, wire_len))
            if pl and len(st["pay"]) < MAX_PAY_PKTS:
                st["pay"].append(f"{sign_char}{pl[:MAX_PAY_HEX_BYTES].hex()}")
            if is_up and pl:
                if proto == "tcp" and len(st["cbuf"]) < 2048:
                    st["cbuf"].extend(pl[: 2048 - len(st["cbuf"])])
                if st["http_host"] is None and len(st["seq"]) <= 4:
                    st["http_host"] = parse_http_host_header(pl)

    records: List[Dict[str, Any]] = []
    for st in archived + list(streams.values()):
        if not st["seq"]:
            continue
        cbuf_b = bytes(st["cbuf"])
        sni, alpn = parse_tls_client_hello_sni_alpn(cbuf_b) if cbuf_b[:1] == b"\x16" else (None, None)
        dns_name = dns_ip_to_domain.get(st["sip"])

        est_mss: Optional[int] = None
        ov_up_pkts = 0
        ov_down_pkts = 0
        ov_up_equiv = 0
        ov_down_equiv = 0

        norm_up_pkts = st["raw_wire_up_pkts"]
        norm_up_chunk_pkts = st["raw_wire_up_chunk_pkts"]
        norm_up_ack_pkts = st["raw_wire_up_ack_pkts"]
        norm_down_pkts = st["raw_wire_down_pkts"]
        norm_down_ack_pkts = st["raw_wire_down_ack_pkts"]
        norm_down_chunk_pkts = st["raw_wire_down_chunk_pkts"]
        seq_out = list(st["seq"])

        if st["proto"] == "tcp":
            is_ipv6 = ":" in st["client"] or ":" in st["sip"]
            fallback_mss = DEFAULT_FALLBACK_MSS_IPV6 if is_ipv6 else DEFAULT_FALLBACK_MSS_IPV4
            bkey = st["bidir_key"]
            est_mss = bidir_tcp_max_non_jumbo.get(bkey, fallback_mss) if bkey is not None else fallback_mss

            if st["oversized_up_hist"]:
                ov_up_pkts, ov_up_equiv, d_pkts, d_chunk, d_ack = _fold_oversized_tcp_counter(
                    st["oversized_up_hist"], est_mss
                )
                norm_up_pkts += d_pkts
                norm_up_chunk_pkts += d_chunk
                norm_up_ack_pkts += d_ack

            if st["oversized_down_hist"]:
                ov_down_pkts, ov_down_equiv, d_pkts, d_chunk, d_ack = _fold_oversized_tcp_counter(
                    st["oversized_down_hist"], est_mss
                )
                norm_down_pkts += d_pkts
                norm_down_chunk_pkts += d_chunk
                norm_down_ack_pkts += d_ack

            if st["seq_oversized_meta"]:
                for seq_idx, sign_char, hdr_len, wire_len in st["seq_oversized_meta"]:
                    eff_mss = est_mss if wire_len > est_mss else max(
                        MIN_VALID_TCP_MSS, STANDARD_ETHERNET_MTU - hdr_len
                    )
                    if wire_len > eff_mss:
                        seq_out[seq_idx] = f"{sign_char}{eff_mss}"

        records.append(
            {
                "fsk_version": FSK_SCHEMA_VERSION_V2_PA,
                "client": st["client"],
                "cport": st["cport"],
                "sip": st["sip"],
                "sport": st["sport"],
                "server": st["server"],
                "dst_port": st["dst_port"],
                "proto": st["proto"],
                "t0": round(st["t0"], 4),
                "t_end": round(st["t_end"], 4),
                "seq": seq_out,
                "pay": st["pay"],
                "sni": sni or st["http_host"],
                "alpn": alpn,
                "dns": dns_name,
                "wire_up_bytes": st["wire_up_bytes"],
                "wire_down_bytes": st["wire_down_bytes"],
                "wire_up_pkts": norm_up_pkts,
                "wire_down_pkts": norm_down_pkts,
                "wire_up_chunk_pkts": norm_up_chunk_pkts,
                "wire_down_ack_pkts": norm_down_ack_pkts,
                "wire_down_chunk_pkts": norm_down_chunk_pkts,
                "wire_up_ack_pkts": norm_up_ack_pkts,
                "est_mss": est_mss,
                "oversized_up_pkts": ov_up_pkts,
                "oversized_down_pkts": ov_down_pkts,
                "oversized_up_equiv_segs": ov_up_equiv,
                "oversized_down_equiv_segs": ov_down_equiv,
                "raw_wire_up_pkts": st["raw_wire_up_pkts"],
                "raw_wire_up_chunk_pkts": st["raw_wire_up_chunk_pkts"],
                "raw_wire_down_pkts": st["raw_wire_down_pkts"],
                "raw_wire_down_ack_pkts": st["raw_wire_down_ack_pkts"],
            }
        )
    return records


def parse_capture_stream_to_flow_records(raw_stream: BinaryIO, filename: str = "") -> List[Dict[str, Any]]:
    """
    Parse any `.pcap`, `.pcap.gz`, `.pcapng`, `.pcapng.gz`, `.fsk.jsonl`, or `.fsk.jsonl.gz`
    stream into TSO/GSO-normalized FlowSketch v2 (`2.0-pa`) dictionary records.
    """
    head2 = raw_stream.read(2)
    if not head2:
        return []

    if head2 == b"\x1f\x8b" or filename.endswith(".gz"):
        chained = _ChainedStream(head2, raw_stream)
        with gzip.GzipFile(fileobj=chained, mode="rb") as gz:
            return _parse_decompressed_stream(gz)

    chained = _ChainedStream(head2, raw_stream)
    return _parse_decompressed_stream(chained)


def parse_capture_bytes_to_flow_records(raw_bytes: bytes, filename: str = "") -> List[Dict[str, Any]]:
    return parse_capture_stream_to_flow_records(io.BytesIO(raw_bytes), filename=filename)


def convert_pcap_file_to_flowsketch_gz(
    input_path: Path,
    output_path: Optional[Path] = None,
    compresslevel: int = 6,
) -> Dict[str, Any]:
    """
    Stream-convert a local `.pcap` / `.pcap.gz` / `.pcapng` file into a compact `.fsk.jsonl.gz`
    FlowSketch v2 (`2.0-pa`) archive suitable for `< 8 MB` edge upload.
    """
    t0 = time.perf_counter()
    in_size = input_path.stat().st_size
    with input_path.open("rb") as fin:
        records = parse_capture_stream_to_flow_records(fin, filename=input_path.name)

    if output_path is None:
        stem = input_path.name
        for suf in (".pcap.gz", ".pcapng.gz", ".pcap", ".pcapng"):
            if stem.endswith(suf):
                stem = stem[: -len(suf)]
                break
        output_path = input_path.parent / f"{stem}.v2.fsk.jsonl.gz"

    buf = io.BytesIO()
    tot_ov_up = 0
    tot_ov_down = 0
    with gzip.GzipFile(filename="sketch.v2.fsk.jsonl", mode="wb", fileobj=buf, compresslevel=compresslevel, mtime=0) as gz:
        for rec in records:
            tot_ov_up += int(rec.get("oversized_up_pkts") or 0)
            tot_ov_down += int(rec.get("oversized_down_pkts") or 0)
            compact = {k: v for k, v in rec.items() if v is not None and v != [] and v != ""}
            gz.write((json.dumps(compact, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
    gz_bytes = buf.getvalue()
    output_path.write_bytes(gz_bytes)
    out_size = len(gz_bytes)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    ratio = round(in_size / max(1, out_size), 2)
    return {
        "fsk_version": FSK_SCHEMA_VERSION_V2_PA,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "input_bytes": in_size,
        "output_bytes": out_size,
        "compression_ratio": ratio,
        "flows_extracted": len(records),
        "oversized_up_pkts_normalized": tot_ov_up,
        "oversized_down_pkts_normalized": tot_ov_down,
        "output_sha256": hashlib.sha256(gz_bytes).hexdigest(),
        "elapsed_ms": elapsed_ms,
        "fits_edge_8mb_wan_cap": out_size <= 8 * 1024 * 1024,
    }


def build_synthetic_demo_pcap_bytes(include_tso_superframe: bool = True) -> bytes:
    """
    Generate a deterministic synthetic PCAP in memory (Ethernet + IPv4 + TCP TLS ClientHello +
    optional 4080-byte TSO super-frame) for offline unit testing and probe `--self-test`.
    """
    out = io.BytesIO()
    # Classic little-endian microsecond PCAP global header (DLT_EN10MB = 1)
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    sni_host = b"api.janusflow.net"
    # RFC 6066: ext_type(2) | ext_len(2) | server_name_list_len(2) | name_type(1) | host_name_len(2) | host_name
    sni_ext = struct.pack("!HHHBH", 0, len(sni_host) + 5, len(sni_host) + 3, 0, len(sni_host)) + sni_host
    alpn_proto = b"\x02h2"
    alpn_ext = struct.pack("!HHH", 16, len(alpn_proto) + 2, len(alpn_proto)) + alpn_proto
    exts = sni_ext + alpn_ext
    ch_body = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs_msg = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    tls_rec = b"\x16\x03\x01" + struct.pack("!H", len(hs_msg)) + hs_msg

    def _add_tcp_frame(ts_us: int, src_ip: str, dst_ip: str, sp: int, dp: int, payload: bytes, wire_pl_len: int) -> None:
        eth = (b"\x00\x11\x22\x33\x44\x55" * 2) + b"\x08\x00"
        ip_tot = 20 + 20 + wire_pl_len
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_tot,
            1,
            0,
            64,
            6,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        tcp_hdr = struct.pack("!HHIIBBHHH", sp, dp, 100, 100, 0x50, 0x18, 64240, 0, 0)
        frame = eth + ip_hdr + tcp_hdr + payload
        orig_len = 14 + ip_tot
        out.write(struct.pack("<IIII", 1700000000, ts_us, len(frame), orig_len))
        out.write(frame)

    c_ip = "10.10.1.50"
    s_ip = "93.184.216.34"
    # 1. ClientHello (uplink)
    _add_tcp_frame(1000, c_ip, s_ip, 54321, 443, tls_rec, len(tls_rec))
    # 2. ServerHello / standard 1360B MSS segment (downlink)
    _add_tcp_frame(2000, s_ip, c_ip, 443, 54321, b"\x16\x03\x03\x05\x4b" + b"\xaa" * 60, 1360)
    # 3. Standard 1360B uplink data segment (establishes est_mss = 1360)
    _add_tcp_frame(3000, c_ip, s_ip, 54321, 443, b"\x17\x03\x03\x05\x4b" + b"\xbb" * 60, 1360)
    # 4. Optional 4080B (3 x 1360B) TSO super-frame truncated to snaplen=256
    if include_tso_superframe:
        _add_tcp_frame(4000, c_ip, s_ip, 54321, 443, b"\x17\x03\x03\x0f\xeb" + b"\xcc" * 120, 4080)

    return out.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="janusflow-sketch",
        description="JanusFlow FlowSketch v2 (2.0-pa) Local Pre-Extractor & TSO/GSO Normalizer",
    )
    ap.add_argument("input", nargs="?", help="Input .pcap / .pcap.gz / .pcapng file")
    ap.add_argument("-o", "--output", default=None, help="Output .fsk.jsonl.gz path")
    ap.add_argument(
        "--check-ethtool-file",
        default=None,
        help="Optional path to `ethtool -k` output text to assert tso/gso/gro=off",
    )
    ap.add_argument("--self-test", action="store_true", help="Run built-in FlowSketch v2 + TSO folding self-test")
    args = ap.parse_args()

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
        ap.error("the following arguments are required: input (or pass --self-test)")
    in_p = Path(args.input)
    out_p = Path(args.output) if args.output else None
    meta = convert_pcap_file_to_flowsketch_gz(in_p, output_path=out_p)
    if args.check_ethtool_file:
        eth_txt = Path(args.check_ethtool_file).read_text(encoding="utf-8", errors="ignore")
        meta["ethtool_offload_check"] = verify_ethtool_offloads_disabled(eth_txt)
    print(json.dumps(meta, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
