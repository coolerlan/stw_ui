from __future__ import annotations

import argparse
import base64
import json
import hashlib
import math
import zipfile
import secrets
import re
import ctypes
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from ctypes import wintypes

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    class _NoColor:
        RED = ""
        RESET_ALL = ""
    Fore = _NoColor()
    Style = _NoColor()
    def colorama_init():
        return None

colorama_init()

try:
    import psutil
except ImportError:
    psutil = None

try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None
    win32process = None


DEFAULT_DUMPCAP_PATH = r"D:\WiresharkPortable64\App\Wireshark\dumpcap.exe"
DEFAULT_INTERFACE = "10"
DEFAULT_PORT = 9065
STW_PROCESS_NAME = "STW0.30.exe"
GAME_PROCESS_NAME = "sa_2903.exe"
SCRIPT_WINDOW_TEXT = "脚本制作"
TABLE = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}"


def make_l2_key(account: str) -> str:
    """Game field-layer key: account + literal bing."""
    return f"{account}bing"


def _swap(src4: bytes, rule: bytes) -> bytes:
    dst = bytearray(4)
    for i in range(4):
        dst[int(chr(rule[i])) - 1] = src4[i]
    return bytes(dst)


def _64to256(src: bytes) -> Optional[bytes]:
    dw = 0
    out = bytearray()
    for i, c in enumerate(src):
        try:
            idx = TABLE.index(c)
        except ValueError:
            return None
        if i % 4:
            dw = (idx << ((4 - (i % 4)) * 2)) | dw
            out.append(dw & 0xFF)
            dw >>= 8
        else:
            dw = idx
    if dw:
        out.append(dw & 0xFF)
    return bytes(out)


def decode_layer1(src: bytes) -> Optional[bytes]:
    """Decode one newline-framed SA application message."""
    if src.endswith(b"\n"):
        src = src[:-1]
    if not src:
        return None

    tz = bytes(x ^ 0xFF for x in src)
    head = _64to256(tz[:6])
    if not head or len(head) < 4:
        return None

    t2 = (int.from_bytes(head[:4], "little") ^ 0xFFFFFFFF) & 0xFFFFFFFF
    rn = int.from_bytes(_swap(t2.to_bytes(4, "little"), b"3142"), "little", signed=True)
    body = tz[6:]
    if not body:
        return b""

    offs = len(body) - (rn % len(body))
    return body[offs:] + body[:offs]


def _decode64(src: bytes, key: str | bytes, mode: str) -> Optional[bytes]:
    if isinstance(key, str):
        key = key.encode("latin1", "replace")
    if not key:
        return None

    dw = 0
    out = bytearray()
    j = 0
    for i, c in enumerate(src):
        try:
            idx = TABLE.index(c)
        except ValueError:
            return None

        if mode == "shr":
            val = (idx + key[j]) % 64
        else:
            val = (idx + 64 - key[j]) % 64
        j = (j + 1) % len(key)

        if i % 4:
            dw = (val << ((4 - (i % 4)) * 2)) | dw
            out.append(dw & 0xFF)
            dw >>= 8
        else:
            dw = val

    if dw:
        out.append(dw & 0xFF)
    return bytes(out)


def destring(field: bytes, key: str | bytes) -> Optional[bytes]:
    return _decode64(field, key, "shr")


def deint(field: bytes, key: str | bytes) -> Optional[int]:
    b = _decode64(field, key, "shl")
    if not b or len(b) < 4:
        return None
    t2 = (int.from_bytes(b[:4], "little") ^ 0xFFFFFFFF) & 0xFFFFFFFF
    return int.from_bytes(_swap(t2.to_bytes(4, "little"), b"2413"), "little", signed=True)


@dataclass
class ProtocolMessage:
    ts: float
    direction: str
    src: str
    sport: int
    dst: str
    dport: int
    decoded: bytes

    @property
    def parts(self) -> List[bytes]:
        return self.decoded.split(b";")

    @property
    def fid(self) -> str:
        p = self.parts
        if len(p) < 2:
            return "?"
        return p[1].decode("ascii", "replace")

    @property
    def fields(self) -> List[bytes]:
        p = self.parts
        return p[2:-2] if len(p) >= 4 else []


class LiveTCPStreamDecoder:
    """Minimal in-order TCP reassembler for newline-framed SA messages."""

    def __init__(self):
        self.expected: Dict[Tuple[str, int, str, int], int] = {}
        self.pending: Dict[Tuple[str, int, str, int], Dict[int, bytes]] = defaultdict(dict)
        self.buffers: Dict[Tuple[str, int, str, int], bytearray] = defaultdict(bytearray)

        # Capture can occasionally miss one TCP segment.  The old reassembler
        # waited forever for that exact sequence number, which meant a
        # long-running instance could permanently stop decoding one direction
        # while a newly-started instance worked immediately.
        #
        # Keep normal TCP reordering tolerance, but if a gap remains for a
        # short period (or pending data grows large), abandon only the broken
        # partial line and resynchronise from the earliest captured segment.
        self.gap_since: Dict[Tuple[str, int, str, int], float] = {}
        self.GAP_RESYNC_SECONDS = 0.75
        self.GAP_RESYNC_SEGMENTS = 32
        self.GAP_RESYNC_BYTES = 64 * 1024

    def feed(self, key: Tuple[str, int, str, int], seq: int, payload: bytes) -> List[bytes]:
        if not payload:
            return []

        exp = self.expected.get(key)
        if exp is None:
            exp = seq

        # Retransmission / overlap.
        if seq < exp:
            trim = exp - seq
            if trim >= len(payload):
                return []
            payload = payload[trim:]
            seq = exp

        # Out-of-order packet: normally hold until the gap is filled.
        #
        # Important recovery case: dumpcap/pcap processing can miss a segment.
        # The previous implementation then waited for that missing sequence
        # number forever.  A later-started Python process appeared to "work
        # better" simply because it initialised expected=seq after the gap.
        if seq > exp:
            pend = self.pending[key]
            pend.setdefault(seq, payload)

            now = time.monotonic()
            started = self.gap_since.setdefault(key, now)
            pending_bytes = sum(len(p) for p in pend.values())

            if (
                now - started < self.GAP_RESYNC_SECONDS
                and len(pend) < self.GAP_RESYNC_SEGMENTS
                and pending_bytes < self.GAP_RESYNC_BYTES
            ):
                return []

            # Permanent/large gap: discard the incomplete protocol line and
            # restart TCP decoding at the earliest segment we actually have.
            # We may lose at most the message spanning the missing segment,
            # but subsequent newline-framed messages become decodable again.
            restart_seq = min(pend)
            exp = restart_seq
            self.expected[key] = exp
            self.buffers[key].clear()
            self.gap_since.pop(key, None)

            payload = pend.pop(restart_seq)
            seq = restart_seq

        chunks = [payload]
        exp += len(payload)
        pend = self.pending[key]

        # Drain every pending segment that now touches or overlaps the
        # contiguous byte range.  The old code only accepted a pending segment
        # whose starting sequence was EXACTLY == exp.  If a retransmission or
        # a segment that filled a gap overlapped an already-pending segment,
        # that segment was stranded forever and this direction could slowly
        # fall behind.  A freshly-started process then looked "better" because
        # it had no stale pending state.
        while pend:
            pseq = min(pend)

            # Still a genuine gap: nothing else is contiguous yet.
            if pseq > exp:
                break

            p = pend.pop(pseq)

            # Entire segment is already covered by bytes we accepted.
            if pseq + len(p) <= exp:
                continue

            # Partial overlap: discard only the duplicate prefix and append the
            # genuinely new suffix.
            if pseq < exp:
                trim = exp - pseq
                p = p[trim:]
                pseq = exp

            chunks.append(p)
            exp += len(p)

        self.expected[key] = exp

        # Clear gap timer only when there is no immediate unresolved gap.
        if not pend or min(pend) <= exp:
            self.gap_since.pop(key, None)
        else:
            self.gap_since.setdefault(key, time.monotonic())

        buf = self.buffers[key]
        for c in chunks:
            buf.extend(c)

        if len(buf) > 2 * 1024 * 1024:
            del buf[:-256 * 1024]

        messages: List[bytes] = []
        while True:
            i = buf.find(b"\n")
            if i < 0:
                break

            raw = bytes(buf[:i])
            del buf[: i + 1]
            candidates = [raw]
            if b"\x00" in raw:
                candidates.append(raw.split(b"\x00")[-1])

            for c in candidates:
                if not c:
                    continue
                dec = decode_layer1(c + b"\n")
                if dec and dec.startswith(b"&;") and b";#;" in dec:
                    messages.append(dec)
                    break

        return messages


def _display_bytes(data: bytes) -> str:
    """Readable console form without losing binary information."""
    try:
        text = data.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text
    except UnicodeDecodeError:
        pass

    try:
        text = data.decode("gb18030")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text
    except UnicodeDecodeError:
        pass

    return "0x" + data.hex()


def _try_text(data: Optional[bytes]) -> Optional[str]:
    """Return a human-readable decoded string, otherwise None."""
    if not data:
        return None
    for enc in ("utf-8", "gb18030"):
        try:
            s = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if not s:
            continue
        if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in s):
            continue
        if not all(ch.isprintable() or ch in "\r\n\t" for ch in s):
            continue
        return s
    return None


def _looks_semantic_text(s: str) -> bool:
    """Prefer text when it visibly carries protocol/string semantics."""
    if not s:
        return False
    if any(ch.isalpha() for ch in s):
        return True
    if any(ch in "|/:,_-.@[](){}=" for ch in s):
        return True
    if " " in s:
        return True
    return False


def decode_typed_field(field: bytes, key: str | bytes):
    """Decode one L2 field and choose int/string/hex automatically."""
    sb = destring(field, key)
    iv = deint(field, key)
    st = _try_text(sb)

    if st is not None and _looks_semantic_text(st):
        return "str", st, st, iv

    if iv is not None:
        if st is None or st.lstrip("+-").isdigit() or not _looks_semantic_text(st):
            return "int", iv, st, iv

    if st is not None:
        return "str", st, st, iv

    if sb is not None:
        return "hex", "0x" + sb.hex(), None, iv
    return "hex", "<decode-failed>", None, iv




def _hex_num(token: str):
    """BC numeric text is hexadecimal. Return (raw, decimal) conservatively."""
    t = token.strip()
    if not t:
        return token, None
    try:
        return token, int(t, 16)
    except ValueError:
        return token, None


def _fmt_hex_num(token: str) -> str:
    raw, dec = _hex_num(token)
    if dec is None:
        return raw if raw else "-"
    if raw.upper() == format(dec, 'X') and raw.isdigit() and dec < 10:
        return str(dec)
    return f"{raw} (dec {dec})"


def parse_bc_records(text: str):
    """Parse a decoded BC payload into repeated 13-field records.

    Observed wire layout from the user's captures:
      BC | slot | name | text2 | entity_id | v1 | v2 | v3 | flag1 | flag2 |
           linked_name | linked_v1 | linked_v2 | linked_v3 | ...

    Numeric fields are represented as hexadecimal text by the protocol.
    Labels v*/flag* remain intentionally conservative until matched to server-side names.
    """
    if not text.startswith("BC|"):
        return None
    toks = text.split('|')
    if toks and toks[-1] == '':
        toks.pop()
    body = toks[1:]
    if not body or len(body) % 13 != 0:
        return {"ok": False, "tokens": body, "reason": f"BC token count {len(body)} is not a multiple of 13"}
    recs=[]
    for n in range(0, len(body), 13):
        r=body[n:n+13]
        recs.append({
            "slot": r[0],
            "name": r[1],
            "text2": r[2],
            "entity_id": r[3],
            "v1": r[4],
            "v2": r[5],
            "v3": r[6],
            "flag1": r[7],
            "flag2": r[8],
            "linked_name": r[9],
            "linked_v1": r[10],
            "linked_v2": r[11],
            "linked_v3": r[12],
        })
    return {"ok": True, "records": recs}


def print_bc_records(text: str) -> bool:
    parsed = parse_bc_records(text)
    if parsed is None:
        return False
    if not parsed.get("ok"):
        print(f"    [BC] parse warning: {parsed.get('reason')}")
        return False
    recs = parsed["records"]
    print(f"    [BC] {len(recs)} records")
    for r in recs:
        slot_raw, slot_dec = _hex_num(r['slot'])
        slot = f"{slot_raw} (dec {slot_dec})" if slot_dec is not None else slot_raw
        name = r['name'] or '<empty>'
        eid = _fmt_hex_num(r['entity_id'])
        line = (
            f"      slot={slot:<12} name={name:<12} id={eid:<20} "
            f"v1={_fmt_hex_num(r['v1'])} v2={_fmt_hex_num(r['v2'])} v3={_fmt_hex_num(r['v3'])} "
            f"flags={_fmt_hex_num(r['flag1'])},{_fmt_hex_num(r['flag2'])}"
        )
        print(line)
        if r['text2']:
            print(f"        text2={r['text2']}")
        if r['linked_name'] or any(x not in ('', '0') for x in (r['linked_v1'], r['linked_v2'], r['linked_v3'])):
            lname = r['linked_name'] or '<empty>'
            print(
                f"        linked={lname} "
                f"lv1={_fmt_hex_num(r['linked_v1'])} "
                f"lv2={_fmt_hex_num(r['linked_v2'])} "
                f"lv3={_fmt_hex_num(r['linked_v3'])}"
            )
    return True


class CorrelationLearner:
    """Passive v26 correlation learner.

    It never sends packets.  Instead it learns three independent signals:
      1) temporal S>C -> C>S correlations using the *latest server burst*;
      2) per-shape cadence / periodicity;
      3) exact decoded-content signatures seen in both directions.

    The burst model is intentionally conservative: if several server message
    shapes arrive together before a client message, every shape in that burst
    remains an ambiguous candidate and receives only 1/N ambiguity credit.
    This prevents the v25 failure mode where the last message in a burst was
    declared to be the request merely because it happened to be last.
    """

    EXCLUDED_CODES = {"H0", "W0", "BP", "BC", "BA", "BH", "BY"}

    def __init__(
        self,
        log_path: str | None,
        summary_path: str | None,
        window: float = 2.0,
        burst_gap: float = 0.050,
        min_support: int = 20,
        min_score: float = 0.50,
        samples_per_pair: int = 3,
        checkpoint_seconds: float = 30.0,
        include_battle: bool = False,
        cadence_min_period: float = 5.0,
        cadence_bin: float = 0.25,
        announce: bool = True,
    ):
        self.log_path = os.path.abspath(log_path) if log_path else None
        self.summary_path = os.path.abspath(summary_path) if summary_path else None
        self.window = max(0.05, float(window))
        self.burst_gap = max(0.001, min(float(burst_gap), self.window))
        self.min_support = max(3, int(min_support))
        self.min_score = max(0.0, min(1.0, float(min_score)))
        self.samples_per_pair = max(0, min(20, int(samples_per_pair)))
        self.checkpoint_seconds = max(2.0, float(checkpoint_seconds))
        self.include_battle = bool(include_battle)
        self.cadence_min_period = max(0.5, float(cadence_min_period))
        self.cadence_bin = max(0.05, float(cadence_bin))
        self.announce = announce

        self.pending = deque(maxlen=512)
        self.seq = 0
        self.request_counts = Counter()
        self.reply_counts = Counter()
        self.pair_stats = {}
        self.reply_totals_by_request = Counter()
        self.shape_last_ts = {}
        self.cadence_bins = defaultdict(Counter)
        self.cadence_intervals = Counter()
        self.content_counts = defaultdict(Counter)
        self.content_examples = {}
        self.emitted_pair_state = {}
        self.emitted_cadence_state = {}
        self.started_at = time.time()
        self.last_checkpoint_wall = self.started_at
        self.observed_messages = 0
        self.skipped_battle_messages = 0
        self._log_fp = None

        if self.log_path:
            try:
                parent = os.path.dirname(self.log_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                self._log_fp = open(self.log_path, "a", encoding="utf-8", buffering=1)
            except OSError as e:
                print(f"\n[CORR-WARN] cannot open {self.log_path}: {e}")
                self._log_fp = None

        self._write_log({
            "type": "session_start",
            "version": 26,
            "ts": self.started_at,
            "window": self.window,
            "burst_gap": self.burst_gap,
            "min_support": self.min_support,
            "min_score": self.min_score,
            "samples_per_pair": self.samples_per_pair,
            "include_battle": self.include_battle,
            "note": "passive correlation learner; never transmits packets",
        })

    @staticmethod
    def safe_code(code: str) -> bool:
        if not code or code in CorrelationLearner.EXCLUDED_CODES:
            return False
        if len(code) == 2 and code[0] == "K":
            return False
        return True

    @staticmethod
    def message_record(msg: ProtocolMessage, code: str, decoded_values):
        return {
            "ts": float(msg.ts),
            "direction": msg.direction,
            "code": code,
            "fid": str(msg.fid),
            "decoded_b64": base64.b64encode(msg.decoded).decode("ascii"),
            "fields_b64": [base64.b64encode(v).decode("ascii") for v in (msg.fields or [])],
            "typed": [{"kind": k, "value": v} for k, v in decoded_values],
        }

    @staticmethod
    def _shape(rec):
        return (str(rec.get("fid", "?")), str(rec.get("code", "??")))

    @staticmethod
    def _shape_obj(shape):
        return {"fid": shape[0], "code": shape[1]}

    @staticmethod
    def _shape_text(shape):
        return f"fid={shape[0]} {shape[1]}"

    @staticmethod
    def _compact_record(rec):
        # Full payload is retained only in a tiny capped sample set per pair.
        # This preserves learning material without producing another 20+ MB log.
        return {
            "ts": rec.get("ts"),
            "direction": rec.get("direction"),
            "fid": rec.get("fid"),
            "code": rec.get("code"),
            "typed": rec.get("typed", []),
            "decoded_b64": rec.get("decoded_b64"),
            "fields_b64": rec.get("fields_b64", []),
        }

    @staticmethod
    def _content_signature(rec):
        typed = rec.get("typed") or []
        raw = json.dumps(typed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not raw or raw == b"[]":
            raw = str(rec.get("decoded_b64", "")).encode("ascii", "ignore")
        return hashlib.sha1(raw).hexdigest()[:16]

    def _write_log(self, obj) -> None:
        if not self._log_fp:
            return
        try:
            self._log_fp.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
        except OSError as e:
            print(f"\n[CORR-WARN] write failed: {e}")
            try:
                self._log_fp.close()
            except Exception:
                pass
            self._log_fp = None

    def _announce(self, text: str) -> None:
        if self.announce:
            print(f"\n{text}")
            print("[STREAM] ", end="", flush=True)

    def _update_content_and_cadence(self, rec) -> None:
        direction = rec.get("direction")
        shape = self._shape(rec)
        key = (direction, shape[0], shape[1])
        ts = float(rec.get("ts", 0.0))

        sig = self._content_signature(rec)
        cc = self.content_counts[key]
        cc[sig] += 1
        self.content_examples.setdefault(sig, rec.get("typed", []))
        if len(cc) > 64:
            # Keep only the dominant content variants; exact long-tail payloads
            # are not useful for keepalive/correlation discovery.
            self.content_counts[key] = Counter(dict(cc.most_common(32)))

        prev = self.shape_last_ts.get(key)
        if prev is not None and ts > prev:
            dt = ts - prev
            self.cadence_intervals[key] += 1
            bucket = round(dt / self.cadence_bin) * self.cadence_bin
            self.cadence_bins[key][bucket] += 1
            if len(self.cadence_bins[key]) > 512:
                self.cadence_bins[key] = Counter(dict(self.cadence_bins[key].most_common(256)))
        self.shape_last_ts[key] = ts

    def _purge_pending(self, now: float) -> None:
        while self.pending and (now - self.pending[0]["ts"] > self.window):
            self.pending.popleft()

    def _new_pair_stat(self):
        return {
            "count": 0,
            "lag_sum": 0.0,
            "lag_sq_sum": 0.0,
            "lag_min": None,
            "lag_max": None,
            "ambiguity_credit": 0.0,
            "burst_size_sum": 0,
            "singleton_count": 0,
            "samples": [],
        }

    def _record_pair(self, req_item, reply_rec, burst_shapes) -> None:
        rshape = req_item["shape"]
        cshape = self._shape(reply_rec)
        key = (rshape, cshape)
        st = self.pair_stats.get(key)
        if st is None:
            st = self._new_pair_stat()
            self.pair_stats[key] = st
        lag = max(0.0, float(reply_rec.get("ts", 0.0)) - req_item["ts"])
        burst_n = max(1, len(burst_shapes))
        st["count"] += 1
        st["lag_sum"] += lag
        st["lag_sq_sum"] += lag * lag
        st["lag_min"] = lag if st["lag_min"] is None else min(st["lag_min"], lag)
        st["lag_max"] = lag if st["lag_max"] is None else max(st["lag_max"], lag)
        st["ambiguity_credit"] += 1.0 / burst_n
        st["burst_size_sum"] += burst_n
        if burst_n == 1:
            st["singleton_count"] += 1
        self.reply_totals_by_request[rshape] += 1

        if len(st["samples"]) < self.samples_per_pair:
            sample = {
                "lag": round(lag, 6),
                "burst_candidates": [self._shape_obj(x) for x in burst_shapes],
                "request": self._compact_record(req_item["rec"]),
                "reply": self._compact_record(reply_rec),
            }
            st["samples"].append(sample)
            self._write_log({
                "type": "pair_sample",
                "request_shape": self._shape_obj(rshape),
                "reply_shape": self._shape_obj(cshape),
                **sample,
            })

        self._maybe_emit_pair_state(key, st)

    def _pair_metrics(self, key, st):
        rshape, cshape = key
        support = st["count"]
        req_total = max(1, self.request_counts[rshape])
        paired_total = max(1, self.reply_totals_by_request[rshape])
        coverage = min(1.0, support / req_total)
        purity = min(1.0, support / paired_total)
        ambiguity = st["ambiguity_credit"] / support if support else 0.0
        singleton_ratio = st["singleton_count"] / support if support else 0.0
        mean = st["lag_sum"] / support if support else 0.0
        var = max(0.0, st["lag_sq_sum"] / support - mean * mean) if support else 0.0
        std = math.sqrt(var)
        cv = std / max(mean, 0.050)
        stability = 1.0 / (1.0 + cv)
        # Coverage/purity say "does this reply follow this request?" while
        # ambiguity says "was the request isolated enough to assign credit?".
        score = math.sqrt(max(0.0, coverage * purity)) * (0.25 + 0.75 * ambiguity) * stability
        avg_burst = st["burst_size_sum"] / support if support else 0.0
        if support >= self.min_support and coverage >= 0.55 and purity >= 0.75:
            if ambiguity < 0.60:
                label = "ambiguous"
            elif score >= self.min_score:
                label = "strong"
            else:
                label = "candidate"
        elif support >= self.min_support:
            label = "weak"
        else:
            label = "learning"
        return {
            "support": support,
            "request_total": self.request_counts[rshape],
            "coverage": round(coverage, 4),
            "purity": round(purity, 4),
            "ambiguity_credit": round(ambiguity, 4),
            "singleton_ratio": round(singleton_ratio, 4),
            "avg_burst_size": round(avg_burst, 3),
            "lag_mean": round(mean, 6),
            "lag_std": round(std, 6),
            "lag_min": round(st["lag_min"], 6) if st["lag_min"] is not None else None,
            "lag_max": round(st["lag_max"], 6) if st["lag_max"] is not None else None,
            "score": round(score, 4),
            "label": label,
        }

    def _maybe_emit_pair_state(self, key, st) -> None:
        m = self._pair_metrics(key, st)
        if m["support"] < self.min_support:
            return
        state = m["label"]
        prev = self.emitted_pair_state.get(key)
        if prev == state:
            return
        self.emitted_pair_state[key] = state
        rshape, cshape = key
        self._write_log({
            "type": "correlation_state",
            "request_shape": self._shape_obj(rshape),
            "reply_shape": self._shape_obj(cshape),
            **m,
        })
        tag = {"strong": "CORR", "ambiguous": "AMBIG", "candidate": "CAND", "weak": "WEAK"}.get(state, "LEARN")
        self._announce(
            f"[{tag}] {self._shape_text(rshape)} -> {self._shape_text(cshape)} "
            f"n={m['support']} cov={m['coverage']:.2f} purity={m['purity']:.2f} "
            f"amb={m['ambiguity_credit']:.2f} lag={m['lag_mean']:.3f}s score={m['score']:.2f}"
        )

    def observe_record(self, rec, in_battle: bool = False) -> None:
        code = str(rec.get("code", ""))
        direction = rec.get("direction")
        if direction not in {"S>C", "C>S"} or not self.safe_code(code):
            return
        self.observed_messages += 1
        self._update_content_and_cadence(rec)

        now = float(rec.get("ts", 0.0))
        self._purge_pending(now)
        shape = self._shape(rec)

        if direction == "S>C":
            self.request_counts[shape] += 1
            if in_battle and not self.include_battle:
                self.skipped_battle_messages += 1
            else:
                self.seq += 1
                self.pending.append({"ts": now, "seq": self.seq, "shape": shape, "rec": rec})
            self._maybe_checkpoint()
            return

        self.reply_counts[shape] += 1
        if in_battle and not self.include_battle:
            self.skipped_battle_messages += 1
            self._maybe_checkpoint()
            return
        if not self.pending:
            self._maybe_checkpoint()
            return

        # Only the latest server *burst* competes for this client message.
        # Keeping every distinct shape in that burst is the key v26 change.
        latest_ts = self.pending[-1]["ts"]
        burst = [x for x in self.pending if latest_ts - x["ts"] <= self.burst_gap]
        latest_by_shape = {}
        for item in burst:
            latest_by_shape[item["shape"]] = item
        chosen = list(latest_by_shape.values())
        chosen.sort(key=lambda x: x["seq"])
        burst_shapes = tuple(x["shape"] for x in chosen)
        if chosen and 0.0 <= now - latest_ts <= self.window:
            consumed = {x["seq"] for x in burst}
            for item in chosen:
                self._record_pair(item, rec, burst_shapes)
            if consumed:
                self.pending = deque((x for x in self.pending if x["seq"] not in consumed), maxlen=512)
        self._maybe_checkpoint()

    def _cadence_candidate(self, key):
        bins = self.cadence_bins.get(key)
        total = self.cadence_intervals.get(key, 0)
        if not bins or total < max(8, self.min_support // 2):
            return None
        candidates = [(b, n) for b, n in bins.items() if b >= self.cadence_min_period and n >= 3]
        if not candidates:
            return None
        best = None
        for base, direct_n in candidates:
            tol = max(self.cadence_bin * 1.5, base * 0.02)
            harmonic = 0
            for interval, n in bins.items():
                k = max(1, int(round(interval / base)))
                if k <= 20 and abs(interval - k * base) <= tol * k:
                    harmonic += n
            ratio = harmonic / max(1, total)
            score = ratio * math.log1p(harmonic) * (1.0 + min(1.0, direct_n / 10.0) * 0.10)
            cand = (score, -base, base, direct_n, harmonic, ratio)
            if best is None or cand > best:
                best = cand
        if best is None:
            return None
        _, _, base, direct_n, harmonic, ratio = best
        if direct_n < 5 or harmonic < 8 or ratio < 0.30:
            return None
        return {
            "direction": key[0],
            "fid": key[1],
            "code": key[2],
            "base_period": round(base, 3),
            "direct_interval_hits": direct_n,
            "harmonic_hits": harmonic,
            "intervals": total,
            "harmonic_ratio": round(ratio, 4),
        }

    def _content_matches(self):
        by_sig = defaultdict(list)
        for key, counts in self.content_counts.items():
            for sig, n in counts.items():
                if n >= 2:
                    by_sig[sig].append((key, n))
        out = []
        for sig, items in by_sig.items():
            srv = [(k, n) for k, n in items if k[0] == "S>C"]
            cli = [(k, n) for k, n in items if k[0] == "C>S"]
            if not srv or not cli:
                continue
            support = min(max(n for _, n in srv), max(n for _, n in cli))
            out.append({
                "signature": sig,
                "support": support,
                "server_shapes": [
                    {"fid": k[1], "code": k[2], "count": n}
                    for k, n in sorted(srv, key=lambda x: -x[1])[:8]
                ],
                "client_shapes": [
                    {"fid": k[1], "code": k[2], "count": n}
                    for k, n in sorted(cli, key=lambda x: -x[1])[:8]
                ],
                "typed_example": self.content_examples.get(sig, []),
            })
        out.sort(key=lambda x: (-x["support"], x["signature"]))
        return out[:50]

    @staticmethod
    def _heartbeat_families(cadence, content_matches):
        """Combine cadence + exact content symmetry without claiming causality."""
        cmap = {
            (x["direction"], str(x["fid"]), str(x["code"])): x
            for x in cadence
        }
        out = []
        for match in content_matches:
            for sshape in match.get("server_shapes", []):
                skey = ("S>C", str(sshape.get("fid")), str(sshape.get("code")))
                sc = cmap.get(skey)
                if not sc:
                    continue
                for cshape in match.get("client_shapes", []):
                    ckey = ("C>S", str(cshape.get("fid")), str(cshape.get("code")))
                    cc = cmap.get(ckey)
                    if not cc:
                        continue
                    sp = float(sc["base_period"]); cp = float(cc["base_period"])
                    rel = abs(sp - cp) / max(sp, cp, 1e-9)
                    if rel > 0.08:
                        continue
                    out.append({
                        "server": {"fid": skey[1], "code": skey[2]},
                        "client": {"fid": ckey[1], "code": ckey[2]},
                        "content_signature": match.get("signature"),
                        "typed_example": match.get("typed_example", []),
                        "server_period": sp,
                        "client_period": cp,
                        "period_delta_ratio": round(rel, 4),
                        "content_support": match.get("support", 0),
                        "classification": "same-content/same-cadence family; causality not established",
                    })
        out.sort(key=lambda x: (-x["content_support"], x["period_delta_ratio"]))
        return out[:50]

    def build_summary(self):
        correlations = []
        for key, st in self.pair_stats.items():
            m = self._pair_metrics(key, st)
            if m["support"] < 3:
                continue
            correlations.append({
                "request": self._shape_obj(key[0]),
                "reply": self._shape_obj(key[1]),
                **m,
                "samples": st["samples"],
            })
        correlations.sort(key=lambda x: (-x["score"], -x["support"], x["request"]["fid"], x["reply"]["fid"]))

        cadence = []
        for key in self.cadence_bins:
            c = self._cadence_candidate(key)
            if c:
                cadence.append(c)
        cadence.sort(key=lambda x: (-x["harmonic_ratio"], -x["harmonic_hits"], x["base_period"]))

        content_matches = self._content_matches()
        heartbeat_families = self._heartbeat_families(cadence, content_matches)

        return {
            "format": "v26-correlation-summary",
            "generated_at": time.time(),
            "settings": {
                "window": self.window,
                "burst_gap": self.burst_gap,
                "min_support": self.min_support,
                "min_score": self.min_score,
                "samples_per_pair": self.samples_per_pair,
                "include_battle": self.include_battle,
                "cadence_min_period": self.cadence_min_period,
                "cadence_bin": self.cadence_bin,
            },
            "counts": {
                "observed_messages": self.observed_messages,
                "server_shapes": len(self.request_counts),
                "client_shapes": len(self.reply_counts),
                "correlation_shapes": len(self.pair_stats),
                "skipped_battle_messages_for_temporal_learning": self.skipped_battle_messages,
            },
            "correlations": correlations[:200],
            "cadence_candidates": cadence[:100],
            "cross_direction_content_matches": content_matches,
            "heartbeat_family_candidates": heartbeat_families,
        }

    def write_summary(self) -> None:
        if not self.summary_path:
            return
        data = self.build_summary()
        try:
            parent = os.path.dirname(self.summary_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self.summary_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.summary_path)
        except OSError as e:
            print(f"\n[CORR-WARN] cannot write summary {self.summary_path}: {e}")

    def _maybe_checkpoint(self) -> None:
        now = time.time()
        if now - self.last_checkpoint_wall >= self.checkpoint_seconds:
            self.write_summary()
            self.last_checkpoint_wall = now
            for key in list(self.cadence_bins):
                c = self._cadence_candidate(key)
                if not c:
                    continue
                state = (round(c["base_period"], 2), round(c["harmonic_ratio"], 2))
                if self.emitted_cadence_state.get(key) == state:
                    continue
                self.emitted_cadence_state[key] = state
                self._write_log({"type": "cadence_state", **c})
                self._announce(
                    f"[CADENCE] {c['direction']} fid={c['fid']} {c['code']} ~{c['base_period']:.2f}s "
                    f"harmonic={c['harmonic_hits']}/{c['intervals']} ({c['harmonic_ratio']:.2f})"
                )

    def close(self) -> None:
        self.write_summary()
        self._write_log({"type": "session_end", "ts": time.time(), "observed_messages": self.observed_messages})
        if self._log_fp:
            try:
                self._log_fp.close()
            except Exception:
                pass
            self._log_fp = None


def _iter_v25_learning_events(path: str):
    """Read a v25 reply_learning JSONL or ZIP and reconstruct unique messages."""
    path = os.path.abspath(path)
    events = []
    seen = set()
    seq = 0

    def consume(fp):
        nonlocal seq
        for raw in fp:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            typ = obj.get("type")
            recs = []
            if typ == "pair":
                recs = [obj.get("request"), obj.get("reply")]
            elif typ == "unpaired_server":
                recs = [obj.get("request")]
            else:
                continue
            for rec in recs:
                if not rec or "ts" not in rec:
                    continue
                fpkey = (rec.get("ts"), rec.get("direction"), rec.get("fid"), rec.get("decoded_b64"))
                if fpkey in seen:
                    continue
                seen.add(fpkey)
                seq += 1
                events.append((float(rec.get("ts", 0.0)), seq, rec))

    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path, "r") as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".jsonl")]
            if not names:
                raise ValueError("ZIP contains no .jsonl file")
            # Prefer reply_learning.jsonl, otherwise largest JSONL member.
            name = "reply_learning.jsonl" if "reply_learning.jsonl" in names else max(names, key=lambda n: zf.getinfo(n).file_size)
            with zf.open(name, "r") as fp:
                consume(fp)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            consume(fp)

    events.sort(key=lambda x: (x[0], x[1]))
    for _, _, rec in events:
        yield rec


def analyze_learning_file(path: str, output: str, args) -> None:
    learner = CorrelationLearner(
        log_path=None,
        summary_path=output,
        window=args.learn_window,
        burst_gap=args.learn_burst_gap,
        min_support=args.learn_confirm,
        min_score=args.learn_score,
        samples_per_pair=args.learn_samples,
        checkpoint_seconds=10**9,
        include_battle=True,  # old v25 logs do not carry reliable battle-state context
        cadence_min_period=args.learn_cadence_min,
        cadence_bin=args.learn_cadence_bin,
        announce=False,
    )
    n = 0
    for rec in _iter_v25_learning_events(path):
        learner.observe_record(rec, in_battle=False)
        n += 1
    learner.close()
    summary = learner.build_summary()
    print(f"[ANALYZE] reconstructed unique messages={n}")
    print(f"[ANALYZE] report={os.path.abspath(output)}")
    strong = [x for x in summary["correlations"] if x["label"] in {"strong", "ambiguous", "candidate"}]
    for x in strong[:12]:
        print(
            f"  [{x['label'].upper()}] S>C fid={x['request']['fid']} {x['request']['code']} -> "
            f"C>S fid={x['reply']['fid']} {x['reply']['code']} n={x['support']} "
            f"cov={x['coverage']:.2f} amb={x['ambiguity_credit']:.2f} score={x['score']:.2f}"
        )
    for c in summary["cadence_candidates"][:8]:
        print(
            f"  [CADENCE] {c['direction']} fid={c['fid']} {c['code']} ~{c['base_period']:.2f}s "
            f"harmonic={c['harmonic_hits']}/{c['intervals']}"
        )


# ---------------------------------------------------------------------------
# v31 encounter-entry rescue support
# ---------------------------------------------------------------------------
# Seeded from the user's 870 successful encounter entries captured with v27.
# Only unambiguous mappings with sufficient support are eligible for automatic
# rescue by default. Live successful entries continue to update this model.
V30_RESCUE_SEED = {
    "38000": {"11": 168},
    "8000": {"F": 158},
    "78000": {"11": 156},
    "F8000": {"13": 155},
    "18000": {"F": 144},
    "F8C00": {"13": 27},
    "F8400": {"13": 21},
    "FFC00": {"13": 15},
    "FBC00": {"13": 11},
    "F9C00": {"13": 7},
    "F8211": {"11": 4},
    "78211": {"F": 1, "11": 1},
    "F8E11": {"11": 1},
    "18210": {"10": 1},
}


def _raw_to_6bit_values(src: bytes) -> List[int]:
    """Inverse packing for the protocol's 6-bit alphabet."""
    acc = 0
    nbits = 0
    vals: List[int] = []
    for b in src:
        acc |= int(b) << nbits
        nbits += 8
        while nbits >= 6:
            vals.append(acc & 0x3F)
            acc >>= 6
            nbits -= 6
    if nbits:
        vals.append(acc & 0x3F)
    return vals


def _encode64_field(src: bytes, key: str | bytes, mode: str) -> bytes:
    """Inverse of _decode64 used by the existing L2 decoder."""
    if isinstance(key, str):
        key = key.encode("latin1", "replace")
    if not key:
        raise ValueError("empty L2 key")
    vals = _raw_to_6bit_values(src)
    # The original codec omits a final zero sextet when the decoder's trailing
    # accumulator would also be zero.  This matters for ASCII strings whose
    # last byte has zero high bits (e.g. H|13): canonical H/W is 57 bytes, not 58.
    while len(vals) > 1 and vals[-1] == 0:
        vals.pop()
    out = bytearray()
    for i, val in enumerate(vals):
        k = key[i % len(key)]
        if mode == "string":
            idx = (val - k) % 64
        elif mode == "int":
            idx = (val + k) % 64
        else:
            raise ValueError(f"unknown encode mode: {mode}")
        out.append(TABLE[idx])
    return bytes(out)


def enstring(value: str | bytes, key: str | bytes) -> bytes:
    if isinstance(value, str):
        value = value.encode("gb18030", "replace")
    return _encode64_field(value, key, "string")


def enint(value: int, key: str | bytes) -> bytes:
    """Inverse of deint()."""
    raw = int(value).to_bytes(4, "little", signed=True)
    t2_bytes = bytes((raw[1], raw[3], raw[0], raw[2]))
    packed = (int.from_bytes(t2_bytes, "little") ^ 0xFFFFFFFF) & 0xFFFFFFFF
    return _encode64_field(packed.to_bytes(4, "little"), key, "int")


def encode_layer1(decoded: bytes, rn: Optional[int] = None) -> bytes:
    """Inverse of decode_layer1(); returns one newline-framed wire message."""
    if not decoded:
        raise ValueError("cannot encode empty L1 body")
    if rn is None:
        rn = secrets.randbelow(0x7FFFFFFF)
    rn = int(rn)
    if not (0 <= rn <= 0x7FFFFFFF):
        raise ValueError("v31 encoder uses a non-negative signed 31-bit rn")

    raw_rn = rn.to_bytes(4, "little", signed=True)
    t2_bytes = bytes((raw_rn[2], raw_rn[0], raw_rn[3], raw_rn[1]))
    head_int = (int.from_bytes(t2_bytes, "little") ^ 0xFFFFFFFF) & 0xFFFFFFFF
    head_vals = _raw_to_6bit_values(head_int.to_bytes(4, "little"))
    if len(head_vals) != 6:
        raise AssertionError("unexpected L1 header width")
    head = bytes(TABLE[v] for v in head_vals)

    r = rn % len(decoded)
    rotated = decoded[r:] + decoded[:r]
    tz = head + rotated
    return bytes(b ^ 0xFF for b in tz) + b"\n"


def build_l2_string_message(fid: int | str, text: str, key: str | bytes) -> bytes:
    txt_bytes = text.encode("gb18030", "replace")
    return (
        b"&;" + str(fid).encode("ascii") + b";" +
        enstring(txt_bytes, key) + b";" +
        enint(len(txt_bytes), key) + b";#;"
    )


def build_entry_rescue_frames(target_hex: str, key: str | bytes) -> Tuple[bytes, bytes, str, str]:
    """Build the two independent fid=14 H/W wire frames.

    stw_engine sends every battle command with a separate Winsock send().  Keep
    rescue framing identical: one complete Layer1 frame per command, never a
    concatenation passed to one send() call.
    """
    target = str(target_hex).upper()
    if not re.fullmatch(r"[0-9A-F]+", target):
        raise ValueError(f"bad target: {target_hex!r}")
    h = f"H|{target}"
    w = f"W|0|{target}"
    h_l2 = build_l2_string_message(14, h, key)
    w_l2 = build_l2_string_message(14, w, key)
    h_wire = encode_layer1(h_l2)
    w_wire = encode_layer1(w_l2)
    if decode_layer1(h_wire) != h_l2 or decode_layer1(w_wire) != w_l2:
        raise RuntimeError("v31 H/W rescue codec self-test failed")
    return h_wire, w_wire, h, w


def build_entry_rescue_payload(target_hex: str, key: str | bytes) -> Tuple[bytes, str, str]:
    """Compatibility wrapper returning concatenated H/W bytes.

    Auto-rescue itself uses build_entry_rescue_frames() and sends the frames
    separately.  This wrapper remains for callers that only need serialized
    bytes or old API compatibility.
    """
    h_wire, w_wire, h, w = build_entry_rescue_frames(target_hex, key)
    return h_wire + w_wire, h, w


def build_escape_rescue_frames(target_hex: str, key: str | bytes) -> Tuple[bytes, bytes, str, str]:
    """Build the two independent fid=14 E/W automatic-escape wire frames.

    The real Engine path sends ``E`` and ``W|0|<target>`` as two battle commands,
    each encoded as its own Layer1 frame and sent separately through the game's
    existing socket.  Rescue must mirror that behavior exactly.
    """
    target = str(target_hex).upper()
    if not re.fullmatch(r"[0-9A-F]+", target):
        raise ValueError(f"bad target: {target_hex!r}")
    e = "E"
    w = f"W|0|{target}"
    e_l2 = build_l2_string_message(14, e, key)
    w_l2 = build_l2_string_message(14, w, key)
    e_wire = encode_layer1(e_l2)
    w_wire = encode_layer1(w_l2)
    if decode_layer1(e_wire) != e_l2 or decode_layer1(w_wire) != w_l2:
        raise RuntimeError("v31 E/W rescue codec self-test failed")
    return e_wire, w_wire, e, w


def build_escape_rescue_payload(target_hex: str, key: str | bytes) -> Tuple[bytes, str, str]:
    """Compatibility wrapper returning concatenated E/W bytes."""
    e_wire, w_wire, e, w = build_escape_rescue_frames(target_hex, key)
    return e_wire + w_wire, e, w


def build_battle_end_ack_payload(key: str | bytes) -> bytes:
    """Build Engine-compatible fid=8(0,0) battle-end acknowledgement."""
    l2 = b"&;8;" + enint(0, key) + b";" + enint(0, key) + b";#;"
    wire = encode_layer1(l2)
    if decode_layer1(wire) != l2:
        raise RuntimeError("v31 fid=8 rescue codec self-test failed")
    return wire


def _typed_native(rec: dict, prefix: str) -> Optional[str]:
    for item in rec.get("typed", []) or []:
        if item.get("kind") == "str" and isinstance(item.get("value"), str):
            value = item["value"]
            if value.startswith(prefix):
                return value
    return None


def _ba_mask_from_record(rec: dict) -> Optional[str]:
    text = _typed_native(rec, "BA|")
    if not text:
        return None
    m = re.match(r"^BA\|([0-9A-Fa-f]+)\|", text)
    return m.group(1).upper() if m else None


def _target_from_h(rec: dict) -> Optional[str]:
    text = _typed_native(rec, "H|")
    if not text:
        return None
    m = re.match(r"^H\|([0-9A-Fa-f]+)$", text)
    return m.group(1).upper() if m else None


def _target_from_w(rec: dict) -> Optional[str]:
    text = _typed_native(rec, "W|0|")
    if not text:
        return None
    m = re.match(r"^W\|0\|([0-9A-Fa-f]+)$", text)
    return m.group(1).upper() if m else None


class RescueTargetModel:
    """Persist a conservative BA-mask -> first-response target model."""

    def __init__(self, path: str, announce: bool = True):
        self.path = os.path.abspath(path)
        self.announce = announce
        self.counts: Dict[str, Counter] = defaultdict(Counter)
        loaded = False
        try:
            if os.path.isfile(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if obj.get("format") in {"v28-rescue-baseline", "v29-rescue-baseline", "v30-rescue-baseline", "v31-rescue-baseline"}:
                    for mask, dist in (obj.get("counts") or {}).items():
                        for target, n in (dist or {}).items():
                            self.counts[str(mask).upper()][str(target).upper()] += int(n)
                    loaded = True
        except Exception as e:
            if self.announce:
                print(f"[RESCUE-WARN] cannot load baseline {self.path}: {e}")
        if not loaded:
            for mask, dist in V30_RESCUE_SEED.items():
                for target, n in dist.items():
                    self.counts[mask][target] += int(n)
            self.write()

    def observe(self, mask: Optional[str], target: Optional[str]) -> None:
        if not mask or not target:
            return
        mask = mask.upper()
        target = target.upper()
        try:
            if not (int(mask, 16) & (1 << int(target, 16))):
                return
        except ValueError:
            return
        self.counts[mask][target] += 1
        self.write()

    def choose(self, mask: Optional[str], min_support: int, min_purity: float):
        if not mask:
            return None, {"reason": "no-ba-mask"}
        mask = mask.upper()
        dist = self.counts.get(mask)
        if not dist:
            return None, {"reason": "unseen-mask", "mask": mask}
        support = int(sum(dist.values()))
        target, best = dist.most_common(1)[0]
        purity = best / support if support else 0.0
        info = {
            "mask": mask,
            "target": target,
            "support": support,
            "purity": round(purity, 6),
            "distribution": dict(dist),
        }
        if support < int(min_support):
            info["reason"] = "insufficient-support"
            return None, info
        if purity < float(min_purity):
            info["reason"] = "ambiguous-target"
            return None, info
        try:
            if not (int(mask, 16) & (1 << int(target, 16))):
                info["reason"] = "target-bit-not-set"
                return None, info
        except ValueError:
            info["reason"] = "invalid-mask-or-target"
            return None, info
        info["reason"] = "ok"
        return target, info

    def choose_escape(self, mask: Optional[str], min_support: int = 1):
        """Choose a valid target for the E/W escape branch.

        For escape, W only needs a target whose bit exists in the current BA
        mask. Multi-target masks legitimately produce different H/W targets, so
        purity=1.0 is not a valid gate here. Prefer this mask's learned dominant
        valid target; if the mask is new, choose a set bit using global observed
        target frequency as a tie-breaker. This guarantees timeout rescue is not
        disabled merely because the encounter had a new/multi-target mask.
        """
        if not mask:
            return None, {"reason": "no-ba-mask"}
        mask = str(mask).upper()
        try:
            mask_value = int(mask, 16)
        except ValueError:
            return None, {"reason": "invalid-mask", "mask": mask}
        if mask_value <= 0:
            return None, {"reason": "empty-mask", "mask": mask}

        dist = self.counts.get(mask) or Counter()
        valid = Counter()
        for target, n in dist.items():
            try:
                bit = int(str(target), 16)
            except ValueError:
                continue
            if 0 <= bit < 64 and (mask_value & (1 << bit)):
                valid[str(target).upper()] += int(n)

        info = {
            "mask": mask,
            "support": int(sum(valid.values())),
            "distribution": dict(dist),
            "valid_distribution": dict(valid),
            "requested_min_support": int(min_support),
        }
        if valid:
            target, best = valid.most_common(1)[0]
            total = int(sum(valid.values()))
            info.update({
                "target": target,
                "target_support": int(best),
                "purity": round(best / total, 6) if total else 0.0,
                "reason": "ok-escape-dominant-valid-target",
            })
            return target, info

        # New mask: any set BA bit is a syntactically valid W target. Rank set
        # bits by how often that target was successfully observed globally, then
        # prefer the lower bit for a stable deterministic tie-break.
        global_targets = Counter()
        for known_dist in self.counts.values():
            for target, n in known_dist.items():
                try:
                    bit = int(str(target), 16)
                except ValueError:
                    continue
                global_targets[bit] += int(n)
        bits = [bit for bit in range(max(1, mask_value.bit_length())) if mask_value & (1 << bit)]
        if not bits:
            info["reason"] = "no-set-target-bit"
            return None, info
        bit = max(bits, key=lambda b: (global_targets.get(b, 0), -b))
        target = format(bit, "X")
        info.update({
            "target": target,
            "target_support": int(global_targets.get(bit, 0)),
            "reason": "ok-escape-mask-bit-fallback",
        })
        return target, info

    def snapshot(self) -> dict:
        return {m: dict(c) for m, c in sorted(self.counts.items())}

    def write(self) -> None:
        try:
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({
                    "format": "v31-rescue-baseline",
                    "updated_at": time.time(),
                    "counts": self.snapshot(),
                    "note": "Seeded from 870 successful v27 entries; updated by observed successful H/W or E/W entry acknowledgements.",
                }, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except OSError as e:
            if self.announce:
                print(f"[RESCUE-WARN] cannot write baseline {self.path}: {e}")


class FridaSocketBridge:
    """Send through the game's existing Winsock when --auto-rescue is enabled."""

    def __init__(self, pid: int, server_port: int, announce: bool = True):
        self.pid = int(pid)
        self.server_port = int(server_port)
        self.announce = announce
        self.session = None
        self.script = None
        self.api = None
        self._lock = threading.Lock()
        try:
            import frida  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "--auto-rescue requires Frida. Install it in the same Python with: pip install frida"
            ) from e

        agent = r"""
const SERVER_PORT = __SERVER_PORT__;
const ws2 = Process.getModuleByName('ws2_32.dll');
const sendPtr = ws2.getExportByName('send');
const wsaSendPtr = ws2.getExportByName('WSASend');
const getpeerPtr = ws2.getExportByName('getpeername');
const geterrPtr = ws2.getExportByName('WSAGetLastError');
const abi = Process.pointerSize === 4 ? 'stdcall' : 'win64';
const sendFn = new NativeFunction(sendPtr, 'int', ['pointer', 'pointer', 'int', 'int'], abi);
const getpeerFn = new NativeFunction(getpeerPtr, 'int', ['pointer', 'pointer', 'pointer'], abi);
const geterrFn = new NativeFunction(geterrPtr, 'int', [], abi);
let lastSocket = ptr(0);
let lastSeenMs = 0;
let observedCalls = 0;
const matchCache = {};

function socketMatches(s) {
  const key = s.toString();
  if (Object.prototype.hasOwnProperty.call(matchCache, key))
    return matchCache[key];
  const sa = Memory.alloc(128);
  const sl = Memory.alloc(4);
  sl.writeU32(128);
  let ok = false;
  try {
    if (getpeerFn(s, sa, sl) === 0) {
      const family = sa.readU16();
      const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      ok = (family === 2 && port === SERVER_PORT);
    }
  } catch (e) {
    ok = false;
  }
  matchCache[key] = ok;
  return ok;
}

function noteSocket(s) {
  observedCalls++;
  if (socketMatches(s)) {
    lastSocket = s;
    lastSeenMs = Date.now();
  }
}

Interceptor.attach(sendPtr, { onEnter(args) { noteSocket(args[0]); } });
Interceptor.attach(wsaSendPtr, { onEnter(args) { noteSocket(args[0]); } });

rpc.exports = {
  status() {
    return {
      ready: !lastSocket.isNull(),
      socket: lastSocket.toString(),
      lastSeenMs: lastSeenMs,
      observedCalls: observedCalls,
      serverPort: SERVER_PORT
    };
  },
  sendbytes(data) {
    if (lastSocket.isNull())
      return {ok: false, error: 'no-matching-game-socket'};
    const n = data.byteLength;
    const mem = Memory.alloc(n);
    mem.writeByteArray(data);
    let sent = 0;
    while (sent < n) {
      const rc = sendFn(lastSocket, mem.add(sent), n - sent, 0);
      if (rc <= 0) {
        return {ok: false, sent: sent, wanted: n, rc: rc, wsaError: geterrFn(), socket: lastSocket.toString()};
      }
      sent += rc;
    }
    lastSeenMs = Date.now();
    return {ok: true, sent: sent, wanted: n, socket: lastSocket.toString()};
  }
};
""".replace("__SERVER_PORT__", str(self.server_port))
        self.session = frida.attach(self.pid)
        self.script = self.session.create_script(agent)
        self.script.on("message", self._on_message)
        self.script.load()
        self.api = self.script.exports_sync
        if self.announce:
            print(f"[RESCUE] Frida bridge attached to PID={self.pid}, peer TCP/{self.server_port}")

    def _on_message(self, message, data):
        if self.announce and isinstance(message, dict) and message.get("type") == "error":
            print(f"\n[RESCUE-FRIDA] {message.get('stack') or message}")

    def status(self) -> dict:
        if self.api is None:
            return {"ready": False, "error": "bridge-not-loaded"}
        try:
            with self._lock:
                return dict(self.api.status())
        except Exception as e:
            return {"ready": False, "error": repr(e)}

    def send(self, payload: bytes) -> dict:
        if self.api is None:
            return {"ok": False, "error": "bridge-not-loaded"}
        try:
            with self._lock:
                return dict(self.api.sendbytes(bytes(payload)))
        except Exception as e:
            return {"ok": False, "error": repr(e)}

    def close(self):
        try:
            if self.script is not None:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session is not None:
                self.session.detach()
        except Exception:
            pass
        self.script = None
        self.session = None
        self.api = None


class EncounterRecorder:
    """v31 encounter black-box + conservative stalled-entry rescue controller.

    BP/BC/BA means the protocol has announced battle entry.  v31 treats both
    observed normal client branches as valid completion of the entry handshake:
    H/W (normal battle action) and 0E/W (automatic escape).  The supplied real
    freeze ended at K1|BP|BC|BA|FFC00 with neither branch and no later application
    payload, so rescue watches only that narrow gap.

    Automatic rescue is opt-in (--auto-rescue).  By default v31 reproduces the
    observed automatic-escape E/W branch through the game's existing Winsock via
    Frida, never by raw TCP packet injection.
    """

    ENTRY_CODES = {"BP", "BC", "BA"}
    ROUTE_CODES = {"13", "P0", "M0", "M1", "15"}
    # In the supplied capture, normal client fid=8 after the strong result tail
    # arrived within 0.015..0.257 s (58 observed cases).  Give the real client
    # 0.5 s to send it itself, then inject one only if it is still missing.
    END8_GRACE_SECONDS = 0.50

    def __init__(
        self,
        log_path: str = "encounter_learning.jsonl",
        summary_path: str = "encounter_summary.json",
        freeze_dir: str = "encounter_freezes",
        pre_seconds: float = 8.0,
        post_seconds: float = 5.0,
        stall_seconds: float = 3.0,
        route_stall: bool = True,
        route_freeze: bool = False,
        log_tcp: bool = False,
        announce: bool = True,
        l2_key: Optional[str] = None,
        auto_rescue: bool = False,
        rescue_bridge: Optional[FridaSocketBridge] = None,
        rescue_action: str = "escape",
        rescue_timeout: float = 1.5,
        rescue_verify_seconds: float = 1.5,
        rescue_baseline_path: str = "encounter_rescue_baseline.json",
        rescue_min_support: int = 5,
        rescue_min_purity: float = 1.0,
        rescue_socket_max_age: float = 120.0,
        rescue_max_attempts: int = 1,
    ):
        self.log_path = os.path.abspath(log_path)
        self.summary_path = os.path.abspath(summary_path)
        self.freeze_dir = os.path.abspath(freeze_dir)
        self.pre_seconds = max(1.0, float(pre_seconds))
        self.post_seconds = max(0.5, float(post_seconds))
        self.stall_seconds = max(1.0, float(stall_seconds))
        self.route_stall = bool(route_stall)
        self.route_freeze = bool(route_freeze)
        self.log_tcp = bool(log_tcp)
        self.announce = bool(announce)

        self.l2_key = l2_key
        self.auto_rescue = bool(auto_rescue)
        self.rescue_action = str(rescue_action).lower().strip()
        if self.rescue_action not in {"escape", "hw"}:
            raise ValueError("rescue_action must be 'escape' or 'hw'")
        self.rescue_bridge = rescue_bridge
        # 870-entry baseline: p99 ~65 ms, extreme normal tail ~1.16 s.
        # Default 1.5 s intentionally sits beyond all supplied normal entries.
        self.rescue_timeout = max(1.0, float(rescue_timeout))
        self.rescue_verify_seconds = max(0.5, float(rescue_verify_seconds))
        self.rescue_min_support = max(1, int(rescue_min_support))
        self.rescue_min_purity = min(1.0, max(0.0, float(rescue_min_purity)))
        self.rescue_socket_max_age = max(5.0, float(rescue_socket_max_age))
        self.rescue_max_attempts = max(1, int(rescue_max_attempts))
        self.target_model = RescueTargetModel(rescue_baseline_path, announce=announce)

        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(self.summary_path) or ".", exist_ok=True)
        os.makedirs(self.freeze_dir, exist_ok=True)
        self._fp = open(self.log_path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.RLock()
        self._stop = threading.Event()

        self.pre = deque(maxlen=4096)
        self.payload_ring = deque(maxlen=4096)
        self.activity_wall = deque(maxlen=2048)
        self.recent_codes = deque(maxlen=64)
        self.active = None
        self.counter = 0

        self.last_message_wall = time.time()
        self.last_message_ts = 0.0
        self.last_message_by_dir = {"S>C": None, "C>S": None}
        self.last_payload_wall = None
        self.last_payload_by_dir = {"S>C": None, "C>S": None}
        self.last_route_wall = None
        self.last_route_ts = None
        self.last_route_stall_key = None
        self.current_in_battle = False
        self.current_escape_armed = False

        self.stats = Counter()
        self.entry_latencies = []          # encounter start -> first valid entry response
        self.entry_response_latencies = [] # first entry BA -> H/W or E/W
        self.entry_hw_latencies = []       # first entry BA -> H/W
        self.entry_escape_latencies = []   # first entry BA -> E/W
        self.stage_counts = Counter()
        self.reply_pairs = defaultdict(lambda: {"count": 0, "lags": []})
        self._active_recent_server = deque(maxlen=64)

        self._watcher = threading.Thread(target=self._watchdog_loop, name="encounter-watchdog", daemon=True)
        self._watcher.start()
        self._write_log({
            "type": "recorder_start",
            "format": "v31-encounter-rescue",
            "wall": time.time(),
            "settings": {
                "pre_seconds": self.pre_seconds,
                "post_seconds": self.post_seconds,
                "stall_seconds": self.stall_seconds,
                "route_stall": self.route_stall,
                "route_freeze": self.route_freeze,
                "log_tcp": self.log_tcp,
                "auto_rescue": self.auto_rescue,
                "rescue_action": self.rescue_action,
                "rescue_timeout": self.rescue_timeout,
                "rescue_verify_seconds": self.rescue_verify_seconds,
                "rescue_min_support": self.rescue_min_support,
                "rescue_min_purity": self.rescue_min_purity,
                "rescue_socket_max_age": self.rescue_socket_max_age,
                "rescue_max_attempts": self.rescue_max_attempts,
            },
        })
        if self.announce:
            mode = "AUTO-RESCUE" if self.auto_rescue else "observe-only"
            print(
                f"[ENC] v31 encounter recorder enabled ({mode}); log={self.log_path}; "
                f"summary={self.summary_path}; freezes={self.freeze_dir}"
            )

    @staticmethod
    def _compact(rec):
        return {
            "ts": rec.get("ts"),
            "direction": rec.get("direction"),
            "fid": rec.get("fid"),
            "code": rec.get("code"),
            "typed": rec.get("typed", []),
            "decoded_b64": rec.get("decoded_b64"),
            "fields_b64": rec.get("fields_b64", []),
        }

    def _write_log(self, obj):
        try:
            self._fp.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
        except OSError as e:
            if self.announce:
                print(f"\n[ENC-WARN] log write failed: {e}")

    def _purge_rings(self, now_wall):
        cutoff = now_wall - self.pre_seconds
        while self.pre and self.pre[0][0] < cutoff:
            self.pre.popleft()
        while self.payload_ring and self.payload_ring[0][0] < cutoff:
            self.payload_ring.popleft()
        while self.activity_wall and self.activity_wall[0] < now_wall - max(10.0, self.pre_seconds):
            self.activity_wall.popleft()

    def _new_session_id(self, ts):
        self.counter += 1
        try:
            stamp = datetime.fromtimestamp(float(ts)).strftime("%Y%m%d_%H%M%S_%f")[:-3]
        except Exception:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        return f"{stamp}_{self.counter:04d}"

    def _start_session(self, trigger, ts, wall):
        if self.active is not None:
            return
        sid = self._new_session_id(ts)
        pre_items = [item[1] for item in self.pre]
        self.active = {
            "id": sid,
            "trigger": trigger,
            "started_ts": float(ts),
            "started_wall": wall,
            "stage": "entry-candidate",
            "entered_ts": None,
            "ended_ts": None,
            "close_after_wall": None,
            "messages": 0,
            "tcp_payloads": 0,
            "stalled": False,
            "saw_bp": False,
            "saw_bc": False,
            # 2026-10-03 live capture: immediately after a successful rescue/BE
            # the next encounter can start with BC->BA and no captured BP.
            # A BC-triggered fresh session is therefore allowed to arm on BA.
            "allow_missing_bp": (str(trigger) == "BC"),
            "entry_ba_ts": None,
            "entry_ba_wall": None,
            "entry_mask": None,
            "entry_h_target": None,
            "entry_w_target": None,
            "entry_escape_seen": False,
            "entry_escape_ts": None,
            "entry_response_kind": None,
            "entry_response_target": None,
            "entry_ack_complete": False,
            "entry_stall_reported": False,
            "client_payload_after_ba": False,
            "server_payload_after_ba": False,
            "client_message_after_ba": False,
            "server_message_after_ba": False,
            "client_codes_after_ba": [],
            "server_codes_after_ba": [],
            "rescue_attempts": 0,
            "rescue_sent_wall": None,
            "rescue_injected": False,
            "rescue_progress": False,
            "rescue_no_progress_reported": False,
            "rescue_blocked": None,
            "rescue_target": None,
            "rescue_end8_sent": False,
            "rescue_end8_wall": None,
        }
        self._active_recent_server.clear()
        self.stats["sessions_started"] += 1
        self.stage_counts["entry-candidate"] += 1
        self._write_log({
            "type": "encounter_start",
            "session": sid,
            "ts": float(ts),
            "trigger": trigger,
            "prebuffer_messages": len(pre_items),
        })
        for x in pre_items:
            y = dict(x)
            y.update({"type": "encounter_message", "session": sid, "phase": "pre"})
            self._write_log(y)
        if self.log_tcp:
            for _, meta in self.payload_ring:
                y = dict(meta)
                y.update({"type": "encounter_tcp", "session": sid, "phase": "pre"})
                self._write_log(y)
        if self.announce:
            print(f"\n[ENC-START] {sid} trigger={trigger}\n[STREAM] ", end="", flush=True)

    def _set_stage(self, stage, ts):
        if self.active is None or self.active.get("stage") == stage:
            return
        self.active["stage"] = stage
        self.stage_counts[stage] += 1
        self._write_log({
            "type": "encounter_stage",
            "session": self.active["id"],
            "ts": float(ts),
            "stage": stage,
        })

    def _end_session(self, reason, ts=None):
        if self.active is None:
            return
        a = self.active
        self._write_log({
            "type": "encounter_end",
            "session": a["id"],
            "ts": float(ts if ts is not None else self.last_message_ts or time.time()),
            "reason": reason,
            "stage": a.get("stage"),
            "messages": a.get("messages", 0),
            "tcp_payloads": a.get("tcp_payloads", 0),
            "stalled": bool(a.get("stalled")),
            "entry_mask": a.get("entry_mask"),
            "entry_ack_complete": bool(a.get("entry_ack_complete")),
            "entry_response_kind": a.get("entry_response_kind"),
            "entry_response_target": a.get("entry_response_target"),
            "rescue_injected": bool(a.get("rescue_injected")),
            "rescue_progress": bool(a.get("rescue_progress")),
        })
        self.stats["sessions_closed"] += 1
        self.active = None
        self._active_recent_server.clear()
        self._write_summary()

    def on_payload(self, payload_len, **meta):
        now_wall = time.time()
        direction = meta.get("direction")
        ts = float(meta.get("ts") or now_wall)
        item = {
            "ts": ts,
            "wall": now_wall,
            "direction": direction,
            "length": int(payload_len),
            "seq": meta.get("seq"),
            "ack": meta.get("ack"),
            "flags": meta.get("flags"),
            "sport": meta.get("sport"),
            "dport": meta.get("dport"),
        }
        with self._lock:
            self.last_payload_wall = now_wall
            if direction in self.last_payload_by_dir:
                self.last_payload_by_dir[direction] = now_wall
            self.payload_ring.append((now_wall, item))
            self._purge_rings(now_wall)
            if self.active is not None:
                a = self.active
                a["tcp_payloads"] += 1
                ba_ts = a.get("entry_ba_ts")
                # Use capture timestamps here, not callback wall-clock timing.
                # A following packet may be delivered to Python immediately
                # after BA even though it is later on the wire.
                if ba_ts is not None and ts > float(ba_ts) + 1e-6:
                    if direction == "C>S":
                        a["client_payload_after_ba"] = True
                    elif direction == "S>C":
                        a["server_payload_after_ba"] = True
                if self.log_tcp:
                    y = dict(item)
                    y.update({"type": "encounter_tcp", "session": a["id"], "phase": "live"})
                    self._write_log(y)

    def _record_reply_pair(self, rec):
        if self.active is None:
            return
        now = float(rec.get("ts", 0.0))
        if rec.get("direction") == "S>C":
            self._active_recent_server.append(rec)
            return
        if rec.get("direction") != "C>S" or not self._active_recent_server:
            return
        candidates = [x for x in self._active_recent_server if 0.0 <= now - float(x.get("ts", 0.0)) <= 1.25]
        if not candidates:
            return
        req = candidates[-1]
        key = (str(req.get("fid")), str(req.get("code")), str(rec.get("fid")), str(rec.get("code")))
        lag = now - float(req.get("ts", 0.0))
        st = self.reply_pairs[key]
        st["count"] += 1
        if len(st["lags"]) < 256:
            st["lags"].append(lag)

    def _arm_entry_watch(self, rec, now_ts, now_wall):
        a = self.active
        if a is None or a.get("entry_ba_ts") is not None:
            return
        if not a.get("saw_bc"):
            return
        if not a.get("saw_bp") and not a.get("allow_missing_bp"):
            return
        # Missing-BP fallback is deliberately narrow: the session itself must
        # have been opened by BC, and BA must follow promptly.  This catches the
        # post-rescue BC->BA sequence without treating an arbitrary stale BC as
        # a new battle minutes later.
        if not a.get("saw_bp"):
            if str(a.get("trigger")) != "BC":
                return
            if float(now_wall) - float(a.get("started_wall") or now_wall) > 2.0:
                return
        mask = _ba_mask_from_record(rec)
        a["entry_ba_ts"] = float(now_ts)
        a["entry_ba_wall"] = float(now_wall)
        a["entry_mask"] = mask
        a["client_payload_after_ba"] = False
        a["server_payload_after_ba"] = False
        a["client_message_after_ba"] = False
        a["server_message_after_ba"] = False
        a["client_codes_after_ba"] = []
        a["server_codes_after_ba"] = []
        self.stats["entry_watch_armed"] += 1
        self._set_stage("await-client-entry-ack", now_ts)
        target, model = self.target_model.choose(mask, self.rescue_min_support, self.rescue_min_purity)
        self._write_log({
            "type": "entry_watch_armed",
            "session": a["id"],
            "ts": now_ts,
            "mask": mask,
            "model_target": target,
            "model": model,
            "timeout": self.rescue_timeout,
        })

    def _maybe_complete_entry_ack(self, now_ts, server_code=None):
        """Complete the first client entry response on an observed valid branch.

        Supported branches:
          * H|target then W|0|target  -> legacy normal battle action
          * E then W|0|target         -> automatic escape
          * W|0|target + later S>C battle progress -> current normal fast-battle

        The third branch is important on current captures: the client often sends
        W only.  We do NOT accept W blindly; the target must be a bit in the
        original entry BA mask and the server must subsequently answer with a
        battle-progress opcode (BA/BH/BY/BT/BE/result tail).
        """
        a = self.active
        if a is None or a.get("entry_ack_complete") or a.get("entry_ba_ts") is None:
            return

        ht = a.get("entry_h_target")
        wt = a.get("entry_w_target")
        escape_seen = bool(a.get("entry_escape_seen"))

        kind = None
        target = None
        if escape_seen and wt:
            kind = "escape"
            target = wt
        elif ht and wt:
            if ht != wt:
                if not a.get("entry_target_mismatch_logged"):
                    a["entry_target_mismatch_logged"] = True
                    self._write_log({
                        "type": "entry_target_mismatch",
                        "session": a["id"],
                        "ts": now_ts,
                        "h_target": ht,
                        "w_target": wt,
                        "mask": a.get("entry_mask"),
                    })
                return
            kind = "hw"
            target = ht
        elif wt and server_code in {"BA", "BH", "BY", "BT", "BE", "2T", "1R", "02"}:
            w_ts = a.get("entry_w_ts")
            mask = a.get("entry_mask")
            if w_ts is None or float(now_ts) <= float(w_ts) + 1e-6:
                return
            try:
                if not mask or not (int(str(mask), 16) & (1 << int(str(wt), 16))):
                    return
            except ValueError:
                return
            kind = "w-only"
            target = wt
        else:
            return

        a["entry_ack_complete"] = True
        a["entry_response_kind"] = kind
        a["entry_response_target"] = target
        a["entered_ts"] = float(now_ts)
        self.stats["entered"] += 1
        self.stats[f"entry_response_{kind}"] += 1

        entry_latency = float(now_ts) - float(a["started_ts"])
        response_latency = float(now_ts) - float(a["entry_ba_ts"])
        if 0 <= entry_latency <= 30:
            self.entry_latencies.append(entry_latency)
        if 0 <= response_latency <= 30:
            self.entry_response_latencies.append(response_latency)
            if kind == "escape":
                self.entry_escape_latencies.append(response_latency)
            elif kind == "hw":
                self.entry_hw_latencies.append(response_latency)

        self.target_model.observe(a.get("entry_mask"), target)
        self._set_stage("entry-escape" if kind == "escape" else "in-battle", now_ts)
        self._write_log({
            "type": "entry_ack",
            "session": a["id"],
            "ts": now_ts,
            "mask": a.get("entry_mask"),
            "response_kind": kind,
            "target": target,
            "response_latency": round(response_latency, 6),
            # Kept for compatibility with v28 log readers.
            "hw_latency": round(response_latency, 6) if kind == "hw" else None,
            "rescued": bool(a.get("rescue_injected")),
        })
        if a.get("rescue_injected"):
            self.stats["rescue_entry_response_observed"] += 1

    def _rollover_for_new_encounter(self, code, now_ts, now_wall):
        """Close a stale/completed session before accepting a fresh BP/BC chain.

        v31 fixes a v30 failure captured in rescue.zip: a rescued encounter can
        receive the normal server-side exit sequence while the legacy battle flag
        is already False.  In that case no True->False transition is observed, so
        the session never enters ``post-battle`` and remains active indefinitely.
        A later real BP/BC/BA then inherits the old ``entry_ba_ts`` and its rescue
        watchdog is never armed.

        A fresh BP is therefore treated as a hard encounter boundary whenever the
        active session has already completed its first entry response.  BC remains
        a conservative fallback only for post-battle tails (for captures that miss
        BP).  BA alone is never a rollover anchor.
        """
        a = self.active
        if a is None:
            return False

        in_post_tail = a.get("close_after_wall") is not None or a.get("stage") == "post-battle"
        completed_entry = bool(a.get("entry_ack_complete"))

        reason = None
        if code == "BP" and in_post_tail:
            reason = "new-entry-during-post-tail"
        elif code == "BP" and completed_entry and not self.current_in_battle:
            # Current server builds can emit BP/BC again between rounds of the
            # SAME battle.  Only treat BP as a new encounter after the battle
            # state has actually left battle (or while already in post-tail).
            reason = "fresh-bp-after-completed-entry"
        elif code == "BC" and in_post_tail:
            reason = "new-entry-during-post-tail"
        else:
            return False

        old_id = a.get("id")
        self.stats["encounter_rollovers"] += 1
        if in_post_tail:
            self.stats["post_tail_rollovers"] += 1
        if reason == "fresh-bp-after-completed-entry":
            self.stats["completed_entry_rollovers"] += 1
        self._write_log({
            "type": "encounter_rollover",
            "session": old_id,
            "ts": float(now_ts),
            "reason": reason,
            "new_entry_code": code,
            "old_stage": a.get("stage"),
            "old_entry_ack_complete": completed_entry,
            "battle_flag": self.current_in_battle,
        })
        self._end_session("next-encounter-start", now_ts)
        self._start_session(code, now_ts, now_wall)
        return True

    def observe(self, rec, battle_before=False, battle_after=False, escape_armed=False):
        now_wall = time.time()
        now_ts = float(rec.get("ts") or now_wall)
        code = str(rec.get("code", "??"))
        direction = rec.get("direction")
        full = self._compact(rec)
        full["battle_before"] = bool(battle_before)
        full["battle_after"] = bool(battle_after)
        full["escape_armed"] = bool(escape_armed)

        with self._lock:
            self.current_in_battle = bool(battle_after)
            self.current_escape_armed = bool(escape_armed)
            self.last_message_wall = now_wall
            self.last_message_ts = now_ts
            if direction in self.last_message_by_dir:
                self.last_message_by_dir[direction] = now_wall
            self.activity_wall.append(now_wall)
            self.recent_codes.append((now_ts, direction, code, str(rec.get("fid", "?"))))
            self._purge_rings(now_wall)

            # v31: a fresh BP also terminates any already-acknowledged stale session,
            # not just a normal post-battle tail. This prevents a rescued session
            # with a stale False battle flag from swallowing the next BP/BC/BA.
            self._rollover_for_new_encounter(code, now_ts, now_wall)

            if code in self.ENTRY_CODES and self.active is None:
                self._start_session(code, now_ts, now_wall)
            if (not battle_before) and battle_after and self.active is None:
                self._start_session("battle-state-enter", now_ts, now_wall)

            if code in self.ROUTE_CODES:
                self.last_route_wall = now_wall
                self.last_route_ts = now_ts

            if self.active is not None:
                a = self.active
                a["messages"] += 1
                y = dict(full)
                y.update({"type": "encounter_message", "session": a["id"], "phase": "live"})
                self._write_log(y)
                self._record_reply_pair(rec)

                # Normal completed battles usually send C>S fid=8(0,0) almost
                # immediately after the result tail.  Remember it so the delayed
                # post-battle unlock fallback does not duplicate the real client.
                if direction == "C>S" and (str(rec.get("fid")) == "8" or code == "08"):
                    if not a.get("client_end8_seen"):
                        a["client_end8_seen"] = True
                        a["client_end8_wall"] = now_wall
                        a["end8_due_wall"] = None
                        self.stats["client_end8_seen"] += 1
                        self._write_log({
                            "type": "client_end8_seen",
                            "session": a["id"],
                            "ts": now_ts,
                        })

                # A server BE is a hard battle-end anchor.  Do NOT immediately
                # inject fid=8 here: the real client normally sends its own 08
                # within a few hundred milliseconds, and v3 could race it and
                # produce duplicate fid=8 frames.  Arm the same delayed fallback
                # used for normal completion instead.
                if direction == "S>C" and self._record_has_tag(rec, "BE"):
                    if not a.get("client_end8_seen") and not a.get("rescue_end8_sent"):
                        a["end8_due_wall"] = now_wall + self.END8_GRACE_SECONDS
                        self._write_log({
                            "type": "end8_fallback_armed",
                            "session": a["id"],
                            "ts": now_ts,
                            "delay": self.END8_GRACE_SECONDS,
                            "reason": "server-BE",
                            "rescued": bool(a.get("rescue_injected")),
                        })
                    # Recorder state must close on BE even when the display-state
                    # heuristic missed 2T/1R/1A.  This is what lets a following
                    # BC->BA become a fresh encounter rather than being swallowed
                    # by the old session.
                    self._set_stage("post-battle", now_ts)
                    a["ended_ts"] = now_ts
                    a["close_after_wall"] = now_wall + self.post_seconds
                    a["entry_stall_reported"] = True
                    self.stats["battle_completed_by_be"] += 1

                ba_ts = a.get("entry_ba_ts")
                if ba_ts is not None and now_ts > float(ba_ts) + 1e-6:
                    if direction == "C>S":
                        a["client_message_after_ba"] = True
                        if len(a["client_codes_after_ba"]) < 16:
                            a["client_codes_after_ba"].append(code)
                    elif direction == "S>C":
                        a["server_message_after_ba"] = True
                        if len(a["server_codes_after_ba"]) < 16:
                            a["server_codes_after_ba"].append(code)
                        # Current fast-battle path is commonly W-only.  A server
                        # reply after that W is the acknowledgement; do this
                        # before the watchdog can misclassify the entry as silent.
                        if not a.get("entry_ack_complete"):
                            self._maybe_complete_entry_ack(now_ts, server_code=code)

                if code == "BP":
                    a["saw_bp"] = True
                    self._set_stage("BP", now_ts)
                elif code == "BC":
                    a["saw_bc"] = True
                    self._set_stage("BC", now_ts)
                elif code == "BA":
                    # v31 deliberately does not require battle_before=False ->
                    # battle_after=True here.  The legacy battle flag can remain
                    # stale across an unusual prior exit.  A fresh BP->BC->BA
                    # chain inside this encounter session is the stronger anchor.
                    if a.get("entry_ba_ts") is None and a.get("saw_bc"):
                        self._arm_entry_watch(rec, now_ts, now_wall)
                    elif a.get("rescue_injected") and direction == "S>C" and not a.get("rescue_progress"):
                        a["rescue_progress"] = True
                        self.stats["rescue_server_progress"] += 1
                        self._write_log({
                            "type": "rescue_server_progress",
                            "session": a["id"],
                            "ts": now_ts,
                            "code": code,
                            "mask": _ba_mask_from_record(rec),
                        })

                if a.get("entry_ba_ts") is not None and direction == "C>S":
                    if code == "0E":
                        # Observed automatic-escape branch: E then W|0|target.
                        a["entry_escape_seen"] = True
                        a["entry_escape_ts"] = now_ts
                    elif code == "H0":
                        target = _target_from_h(rec)
                        if target:
                            a["entry_h_target"] = target
                    elif code == "W0":
                        target = _target_from_w(rec)
                        if target:
                            a["entry_w_target"] = target
                            a["entry_w_ts"] = now_ts
                    self._maybe_complete_entry_ack(now_ts)

                if escape_armed and a.get("entry_ack_complete"):
                    self._set_stage("escape-armed", now_ts)

                if battle_before and (not battle_after):
                    if self.auto_rescue and not a.get("client_end8_seen") and not a.get("rescue_end8_sent"):
                        # Whether the exit was natural or rescue-induced, first
                        # allow the real client to send its own fid=8.  Only fill
                        # the hole after the grace period; this avoids v3's
                        # duplicate-08 race.
                        a["end8_due_wall"] = now_wall + self.END8_GRACE_SECONDS
                        self._write_log({
                            "type": "end8_fallback_armed",
                            "session": a["id"],
                            "ts": now_ts,
                            "delay": self.END8_GRACE_SECONDS,
                            "reason": "battle-state-exit",
                            "rescued": bool(a.get("rescue_injected")),
                        })
                    self._set_stage("post-battle", now_ts)
                    a["ended_ts"] = now_ts
                    a["close_after_wall"] = now_wall + self.post_seconds
                    self.stats["battle_completed"] += 1

            self.pre.append((now_wall, full))

    def _recent_activity_count(self, now_wall, seconds=2.5):
        cutoff = now_wall - seconds
        return sum(1 for x in self.activity_wall if x >= cutoff)

    def _freeze_snapshot(self, reason, now_wall, extra=None):
        sid = self.active["id"] if self.active else None
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        path = os.path.join(self.freeze_dir, f"freeze_{stamp}_{reason}.json")
        bridge_status = None
        if self.rescue_bridge is not None:
            bridge_status = self.rescue_bridge.status()
        obj = {
            "format": "v31-freeze-snapshot",
            "reason": reason,
            "wall": now_wall,
            "session": sid,
            "active": dict(self.active) if self.active else None,
            "in_battle_flag": self.current_in_battle,
            "escape_armed": self.current_escape_armed,
            "message_silence": max(0.0, now_wall - self.last_message_wall),
            "payload_silence": None if self.last_payload_wall is None else max(0.0, now_wall - self.last_payload_wall),
            "message_age_by_direction": {
                k: (None if v is None else max(0.0, now_wall - v)) for k, v in self.last_message_by_dir.items()
            },
            "payload_age_by_direction": {
                k: (None if v is None else max(0.0, now_wall - v)) for k, v in self.last_payload_by_dir.items()
            },
            "bridge_status": bridge_status,
            "recent_codes": list(self.recent_codes),
            "recent_messages": [x[1] for x in self.pre],
            "recent_tcp_payloads": [x[1] for x in self.payload_ring],
            "extra": extra or {},
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
        except OSError as e:
            if self.announce:
                print(f"\n[ENC-WARN] freeze snapshot failed: {e}")
            return None
        self._write_log({"type": "freeze_snapshot", "reason": reason, "session": sid, "path": path, "wall": now_wall})
        if self.announce:
            print(f"\n[ENC-STALL] reason={reason} snapshot={path}\n[STREAM] ", end="", flush=True)
        return path

    def _block_rescue(self, reason: str, info: Optional[dict] = None):
        a = self.active
        if a is None:
            return
        a["rescue_blocked"] = reason
        a["stalled"] = True
        self.stats["rescue_blocked"] += 1
        self._set_stage("stalled-entry", self.last_message_ts or time.time())
        self._write_log({
            "type": "rescue_blocked",
            "session": a["id"],
            "ts": self.last_message_ts or time.time(),
            "reason": reason,
            "info": info or {},
        })
        if self.announce:
            print(f"\n[RESCUE-BLOCK] {reason} {info or ''}\n[STREAM] ", end="", flush=True)

    @staticmethod
    def _record_has_tag(rec: dict, tag: str) -> bool:
        """Return True when a decoded string field contains a protocol tag.

        fid=15 can carry combined payloads such as BH|...|BE|...|BY, so checking
        only the display code can miss BE.  Inspect the decoded string tokens.
        """
        wanted = str(tag)
        for item in rec.get("typed", []) or []:
            if item.get("kind") != "str" or not isinstance(item.get("value"), str):
                continue
            if wanted in item["value"].split("|"):
                return True
        return False

    def _send_rescue_end8(self, now_wall: float, reason: str) -> dict:
        """Send Engine-compatible fid=8(0,0) once as a battle unlock ack.

        Used both after an injected escape and as a post-result fallback when
        the real client fails to emit its normal fid=8 within the grace window.
        """
        a = self.active
        if a is None:
            return {"ok": False, "error": "no-active-session"}
        if a.get("rescue_end8_sent"):
            return {"ok": True, "already": True}
        if not self.l2_key or self.rescue_bridge is None:
            return {"ok": False, "error": "rescue-end8-not-ready"}
        try:
            payload = build_battle_end_ack_payload(self.l2_key)
        except Exception as e:
            result = {"ok": False, "error": repr(e)}
        else:
            result = self.rescue_bridge.send(payload)
        self._write_log({
            "type": "rescue_end8",
            "session": a["id"],
            "wall": now_wall,
            "reason": reason,
            "result": result,
        })
        if result.get("ok") and int(result.get("sent", 0)) == len(payload):
            a["rescue_end8_sent"] = True
            a["rescue_end8_wall"] = now_wall
            self.stats["rescue_end8_sent"] += 1
            if self.announce:
                print(f"\n[RESCUE-END8] fid=8(0,0) reason={reason}\n[STREAM] ", end="", flush=True)
        else:
            self.stats["rescue_end8_failed"] += 1
        return result

    def _attempt_rescue(self, now_wall):
        a = self.active
        if a is None or not self.auto_rescue:
            return
        if a.get("rescue_attempts", 0) >= self.rescue_max_attempts:
            self._block_rescue("max-attempts-reached")
            return
        if not self.l2_key:
            self._block_rescue("no-l2-key")
            return
        if self.rescue_bridge is None:
            self._block_rescue("no-socket-bridge")
            return

        # The v31 logs show that unrelated application traffic routinely
        # continues after entry BA even when the required first H/W or E/W
        # branch never completes.  Treating *any* post-BA traffic as progress
        # therefore suppresses rescue exactly when it is needed.  The watchdog
        # already guarantees entry_ack_complete is false; only a completed entry
        # acknowledgement should cancel the rescue attempt.
        if a.get("entry_ack_complete"):
            return

        # Final safety gate: never inject a late escape into a battle the server
        # has already advanced.  This protects against recorder/capture state
        # desynchronisation even if _attempt_rescue() is called from a future
        # path that bypasses the watchdog's own progress check.
        srv = set(a.get("server_codes_after_ba") or [])
        wt_seen = a.get("entry_w_target")
        meaningful = {"BH", "BY", "BT", "BE", "2T", "1R", "02"}
        if (srv & meaningful) or (wt_seen and "BA" in srv):
            self.stats["rescue_suppressed_server_progress"] += 1
            self._write_log({
                "type": "rescue_suppressed",
                "session": a["id"],
                "wall": now_wall,
                "reason": "server-progress-after-entry-ba",
                "target": wt_seen,
                "server_codes_after_ba": list(a.get("server_codes_after_ba") or []),
            })
            return

        if self.rescue_action == "escape":
            # Prefer a target already seen in this same stalled entry, provided
            # it is actually present in the current BA mask.  This handles
            # multi-target encounters without relying on a globally pure mapping.
            target = None
            model = None
            mask = a.get("entry_mask")
            for candidate, source in (
                (a.get("entry_w_target"), "current-w"),
                (a.get("entry_h_target"), "current-h"),
            ):
                if not candidate or not mask:
                    continue
                try:
                    if int(str(mask), 16) & (1 << int(str(candidate), 16)):
                        target = str(candidate).upper()
                        model = {
                            "reason": "current-entry-target",
                            "source": source,
                            "mask": str(mask).upper(),
                            "target": target,
                        }
                        break
                except ValueError:
                    pass
            if not target:
                # Escape does not require a unique battle-action target.  Use the
                # dominant historically valid target even if the same BA mask has
                # legitimately produced other H/W targets during normal play.
                target, model = self.target_model.choose_escape(
                    mask, min_support=self.rescue_min_support
                )
        else:
            target, model = self.target_model.choose(
                a.get("entry_mask"), self.rescue_min_support, self.rescue_min_purity
            )
        if not target:
            self._block_rescue("target-model-rejected", model)
            return

        status = self.rescue_bridge.status()
        if not status.get("ready"):
            self._block_rescue("game-socket-not-ready", status)
            return
        last_seen_ms = status.get("lastSeenMs")
        try:
            age = time.time() - (float(last_seen_ms) / 1000.0)
        except (TypeError, ValueError):
            age = None
        if age is not None and age > self.rescue_socket_max_age:
            self._block_rescue("game-socket-stale", {"socket_age": age, "status": status})
            return

        try:
            if self.rescue_action == "escape":
                first_frame, w_frame, first_cmd, w_cmd = build_escape_rescue_frames(target, self.l2_key)
            else:
                first_frame, w_frame, first_cmd, w_cmd = build_entry_rescue_frames(target, self.l2_key)
        except Exception as e:
            self._block_rescue("codec-error", {
                "error": repr(e),
                "target": target,
                "rescue_action": self.rescue_action,
            })
            return

        # Match stw_engine exactly: one complete battle command per Winsock send.
        # Do NOT concatenate two newline-framed Layer1 packets into one send().
        a["rescue_attempts"] += 1
        first_result = self.rescue_bridge.send(first_frame)
        if first_result.get("ok") and int(first_result.get("sent", 0)) == len(first_frame):
            w_result = self.rescue_bridge.send(w_frame)
        else:
            w_result = {"ok": False, "error": "first-frame-failed", "skipped": True}
        success = (
            first_result.get("ok")
            and int(first_result.get("sent", 0)) == len(first_frame)
            and w_result.get("ok")
            and int(w_result.get("sent", 0)) == len(w_frame)
        )
        event = {
            "type": "rescue_attempt",
            "session": a["id"],
            "wall": now_wall,
            "entry_mask": a.get("entry_mask"),
            "target": target,
            "rescue_action": self.rescue_action,
            "commands": [first_cmd, w_cmd],
            "frame_lengths": [len(first_frame), len(w_frame)],
            "payload_len": len(first_frame) + len(w_frame),
            "model": model,
            "bridge_before": status,
            "frame_results": [first_result, w_result],
            "result": {"ok": bool(success)},
        }
        self._write_log(event)
        if success:
            a["rescue_injected"] = True
            a["rescue_sent_wall"] = now_wall
            a["rescue_target"] = target
            self.stats["rescue_sent"] += 1
            self._set_stage("rescue-sent", self.last_message_ts or time.time())
            if self.announce:
                print(
                    f"\n[RESCUE-SEND] mode={self.rescue_action} mask={a.get('entry_mask')} target={target} "
                    f"{first_cmd} [{len(first_frame)}B] -> {w_cmd} [{len(w_frame)}B] (2 sends)\n[STREAM] ",
                    end="", flush=True,
                )
        else:
            a["stalled"] = True
            self.stats["rescue_send_failed"] += 1
            self._set_stage("stalled-entry", self.last_message_ts or time.time())
            if self.announce:
                print(
                    f"\n[RESCUE-FAIL] first={first_result} second={w_result}\n[STREAM] ",
                    end="", flush=True,
                )

    def _watchdog_loop(self):
        while not self._stop.wait(0.20):
            now_wall = time.time()
            with self._lock:
                self._purge_rings(now_wall)
                a = self.active
                if a is not None:
                    end8_due = a.get("end8_due_wall")
                    if (
                        end8_due is not None
                        and now_wall >= float(end8_due)
                        and not a.get("client_end8_seen")
                        and not a.get("rescue_end8_sent")
                    ):
                        a["end8_due_wall"] = None
                        result = self._send_rescue_end8(now_wall, "post-battle-missing-client-end8")
                        if result.get("ok"):
                            self.stats["end8_fallback_sent"] += 1
                        else:
                            self.stats["end8_fallback_failed"] += 1
                        self._write_summary()

                    deadline = a.get("close_after_wall")
                    if deadline is not None and now_wall >= deadline:
                        self._end_session("post-tail-complete", self.last_message_ts)
                        continue

                    # v31 primary freeze detector: BP/BC/BA (or a post-exit
                    # BC/BA sequence when BP was missed) arrived but neither
                    # valid first-client branch (H/W or automatic-escape E/W)
                    # completed within the conservative timeout.
                    ba_wall = a.get("entry_ba_wall")
                    if ba_wall is not None and not a.get("entry_ack_complete"):
                        age = now_wall - float(ba_wall)
                        if age >= self.rescue_timeout and not a.get("entry_stall_reported"):
                            srv = set(a.get("server_codes_after_ba") or [])
                            wt = a.get("entry_w_target")
                            meaningful = {"BH", "BY", "BT", "BE", "2T", "1R", "02"}
                            progressed = bool(srv & meaningful) or (bool(wt) and "BA" in srv)
                            if progressed:
                                # Defensive fallback for missed/reordered capture
                                # events.  If the server has already processed a
                                # W or emitted battle/result progress, a late E/W
                                # rescue is more dangerous than useful.
                                a["entry_stall_reported"] = True
                                a["entry_ack_complete"] = True
                                a["entry_response_kind"] = "server-progress-fallback"
                                a["entry_response_target"] = wt
                                a["entered_ts"] = self.last_message_ts or now_wall
                                self.stats["entry_watch_cancelled_by_server_progress"] += 1
                                self._write_log({
                                    "type": "entry_watch_cancelled",
                                    "session": a["id"],
                                    "wall": now_wall,
                                    "reason": "server-progress-after-entry-ba",
                                    "entry_mask": a.get("entry_mask"),
                                    "target": wt,
                                    "server_codes_after_ba": list(a.get("server_codes_after_ba") or []),
                                })
                                self._set_stage("in-battle" if self.current_in_battle else "post-battle", self.last_message_ts or now_wall)
                                self._write_summary()
                                continue
                            a["entry_stall_reported"] = True
                            a["stalled"] = True
                            self.stats["missing_entry_response"] += 1
                            self._freeze_snapshot(
                                "missing_entry_response",
                                now_wall,
                                {
                                    "entry_age": age,
                                    "entry_mask": a.get("entry_mask"),
                                    "client_payload_after_ba": a.get("client_payload_after_ba"),
                                    "server_payload_after_ba": a.get("server_payload_after_ba"),
                                    "client_codes_after_ba": a.get("client_codes_after_ba", []),
                                    "server_codes_after_ba": a.get("server_codes_after_ba", []),
                                },
                            )
                            if self.auto_rescue:
                                self._attempt_rescue(now_wall)
                            else:
                                self._set_stage("stalled-entry", self.last_message_ts or now_wall)
                            self._write_summary()

                        if (
                            a.get("rescue_injected")
                            and not a.get("rescue_progress")
                            and not a.get("rescue_no_progress_reported")
                            and a.get("rescue_sent_wall") is not None
                            and now_wall - float(a["rescue_sent_wall"]) >= self.rescue_verify_seconds
                        ):
                            a["rescue_no_progress_reported"] = True
                            self.stats["rescue_no_progress"] += 1
                            self._freeze_snapshot("rescue_no_server_progress", now_wall)
                            self._write_summary()
                        continue

                    # Pre-BA stall remains diagnostic.  It is never auto-sent.
                    stage = str(a.get("stage", ""))
                    if (
                        not a.get("stalled")
                        and stage in {"entry-candidate", "BP", "BC"}
                        and now_wall - self.last_message_wall >= self.stall_seconds
                    ):
                        a["stalled"] = True
                        self.stats["stalled_before_ba"] += 1
                        self._set_stage("stalled-before-ba", self.last_message_ts or now_wall)
                        self._freeze_snapshot("stalled_before_ba", now_wall)
                        self._write_summary()
                    continue

                if not self.route_stall or self.last_route_wall is None:
                    continue
                silence = now_wall - self.last_message_wall
                route_age = now_wall - self.last_route_wall
                activity = self._recent_activity_count(now_wall, 3.0 + self.stall_seconds)
                key = round(self.last_route_wall, 3)
                if (
                    silence >= self.stall_seconds
                    and route_age <= self.stall_seconds + 2.0
                    and activity >= 4
                    and self.last_route_stall_key != key
                ):
                    self.last_route_stall_key = key
                    self.stats["route_stall_candidates"] += 1
                    info = {
                        "route_age": route_age,
                        "silence": silence,
                        "activity_count": activity,
                        "last_route_ts": self.last_route_ts,
                    }
                    # v31 avoids the v28 false-positive freeze files from ordinary
                    # ~3 s route silence. v31 keeps this as a compact diagnostic;
                    # --route-freeze restores the old full snapshot behavior.
                    self._write_log({
                        "type": "route_silence_note",
                        "wall": now_wall,
                        **info,
                    })
                    if self.route_freeze:
                        self._freeze_snapshot("route_transition_silence", now_wall, info)
                    self._write_summary()

    @staticmethod
    def _latency_summary(values):
        if not values:
            return {"count": 0, "mean": None, "min": None, "max": None, "p99": None}
        vals = sorted(float(x) for x in values)
        p99 = vals[int(0.99 * (len(vals) - 1))]
        return {
            "count": len(vals),
            "mean": round(sum(vals) / len(vals), 6),
            "min": round(vals[0], 6),
            "max": round(vals[-1], 6),
            "p99": round(p99, 6),
        }

    def _write_summary(self):
        pairs = []
        for key, st in sorted(self.reply_pairs.items(), key=lambda kv: kv[1]["count"], reverse=True):
            lags = st["lags"]
            pairs.append({
                "request": {"fid": key[0], "code": key[1]},
                "reply": {"fid": key[2], "code": key[3]},
                "count": st["count"],
                "lag_mean": round(sum(lags) / len(lags), 6) if lags else None,
                "lag_min": round(min(lags), 6) if lags else None,
                "lag_max": round(max(lags), 6) if lags else None,
            })
        obj = {
            "format": "v31-encounter-rescue-summary",
            "generated_at": time.time(),
            "stats": dict(self.stats),
            "stage_counts": dict(self.stage_counts),
            "entry_latency": self._latency_summary(self.entry_latencies),
            "entry_ba_to_response_latency": self._latency_summary(self.entry_response_latencies),
            "entry_ba_to_hw_latency": self._latency_summary(self.entry_hw_latencies),
            "entry_ba_to_escape_latency": self._latency_summary(self.entry_escape_latencies),
            "logging": {
                "log_tcp": self.log_tcp,
                "route_silence_enabled": self.route_stall,
                "route_freeze": self.route_freeze,
            },
            "rescue_settings": {
                "auto_rescue": self.auto_rescue,
                "action": self.rescue_action,
                "timeout": self.rescue_timeout,
                "verify_seconds": self.rescue_verify_seconds,
                "min_support": self.rescue_min_support,
                "min_purity": self.rescue_min_purity,
                "socket_max_age": self.rescue_socket_max_age,
                "max_attempts": self.rescue_max_attempts,
            },
            "rescue_target_model": self.target_model.snapshot(),
            "encounter_reply_pairs": pairs[:100],
            "note": (
                "v31 accepts H/W, automatic-escape E/W, and server-confirmed W-only as valid first entry responses, "
                "and rolls a post-battle tail into a fresh encounter immediately when a new BP/BC arrives. "
                "The watchdog only treats BP/BC/BA followed by neither branch as a missing entry response. "
                "Automatic rescue defaults to the learned E/W escape branch and still requires an unambiguous BA target."
            ),
        }
        tmp = self.summary_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.summary_path)
        except OSError as e:
            if self.announce:
                print(f"\n[ENC-WARN] summary write failed: {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    def close(self):
        self._stop.set()
        if self._watcher.is_alive():
            self._watcher.join(timeout=1.0)
        with self._lock:
            if self.active is not None:
                self._end_session("script-stop", self.last_message_ts or time.time())
            self._write_summary()
            self._write_log({"type": "recorder_end", "wall": time.time()})
            try:
                self._fp.close()
            except Exception:
                pass
        if self.rescue_bridge is not None:
            self.rescue_bridge.close()

class ConsoleSink:
    """Compact realtime instruction stream.

    Default output is a single stream of two-character command codes:
        P0|M0|K0|BP|BC|BA|※|H0|W0|BH|...

    Native two-character sub-protocols (K0/BP/BC/BA/BH/BY/...) are preserved.
    Known messages without a native two-character prefix are mapped by the
    display layer (currently fid=1 -> M0, fid=42 -> P0, H| -> H0, W| -> W0).
    """

    BATTLE_INIT_TAIL = ("BP", "BC", "BA")

    # Observed normal battle-end signatures.
    # Kn matches any K0-KF.
    # A: repeated in completed 5/11/12-round captures.
    BATTLE_END_PATTERN_A = ("1A", "1A", "11", "1W", "1A", "Kn", "Kn", "Kn")
    # B: observed when the opponent was defeated.
    BATTLE_END_PATTERN_B = ("13", "1A", "Kn", "Kn", "Kn")
    # C: 0C|2T|1R|1A|Kn|Kn
    BATTLE_END_PATTERN_C = ("0C", "2T", "1R", "1A", "Kn", "Kn")
    # D: 0C|2T|1R|1A|Kn|Kn|Kn
    BATTLE_END_PATTERN_D = ("0C", "2T", "1R", "1A", "Kn", "Kn", "Kn")

    # This tail is NOT escape-specific: it also appears during normal post-battle
    # restoration.  It is considered an escape only if the battle previously
    # showed the observed escape precursor 0E|W0|BA.
    BATTLE_ESCAPE_PREFIX = ("0E", "W0", "BA")
    BATTLE_ESCAPE_TAIL = ("2T", "1R", "1A", "Kn", "Kn", "Kn")
    BATTLE_ESCAPE_TAIL_V2 = ("2T", "1R", "1A", "Kn", "Kn")

    def __init__(
        self,
        show_fields: bool = False,
        show_raw: bool = False,
        account: str | None = None,
        local_port: int | None = None,
        server_port: int = DEFAULT_PORT,
        learn_replies: bool = False,
        learn_log: str = "correlation_learning.jsonl",
        learn_summary: str = "correlation_summary.json",
        learn_window: float = 2.0,
        learn_burst_gap: float = 0.050,
        learn_confirm: int = 20,
        learn_score: float = 0.50,
        learn_samples: int = 3,
        learn_checkpoint: float = 30.0,
        learn_include_battle: bool = False,
        learn_cadence_min: float = 5.0,
        learn_cadence_bin: float = 0.25,
        encounter_enabled: bool = True,
        encounter_log: str = "encounter_learning.jsonl",
        encounter_summary: str = "encounter_summary.json",
        encounter_freeze_dir: str = "encounter_freezes",
        encounter_pre: float = 8.0,
        encounter_tail: float = 5.0,
        encounter_stall: float = 3.0,
        encounter_route_stall: bool = True,
        encounter_route_freeze: bool = False,
        encounter_log_tcp: bool = False,
        game_pid: int | None = None,
        auto_rescue: bool = False,
        rescue_action: str = "escape",
        rescue_timeout: float = 1.5,
        rescue_verify_seconds: float = 1.5,
        rescue_baseline: str = "encounter_rescue_baseline.json",
        rescue_min_support: int = 5,
        rescue_min_purity: float = 1.0,
        rescue_socket_max_age: float = 120.0,
        rescue_max_attempts: int = 1,
    ):
        self.account = account
        self.l2_key = make_l2_key(account) if account else None
        self.packets = 0
        self.messages = 0
        self.show_fields = show_fields
        self.show_raw = show_raw
        self.local_port = local_port
        self.server_port = server_port
        self.auto_bound_port = local_port
        self.flow_scores = defaultdict(int)
        self.recent_codes = []
        self.stream_started = False
        self.in_battle = False
        self.escape_armed = False
        # Tolerant battle state helpers.  Real captures contain harmless state
        # packets between the semantic battle opcodes, so do not rely only on
        # one exact fixed tail.
        self.battle_start_pending = 0
        self.battle_end_pending = 0
        self.battle_end_kn_count = 0
        # Battle-state resynchronisation helpers.  Some battles end without the
        # usual 0C|2T|1R|1A result tail, leaving in_battle stuck True.
        # A long overworld/menu phase followed by a fresh Kx|BP|BC|BA is strong
        # evidence of a new battle and is allowed to re-enter explicitly.
        self.codes_since_battle_init = 10**9
        self.scene_activity_since_init = 0
        self.result_marker_locked = False

        self.auto_rescue = bool(auto_rescue)
        self.rescue_bridge = None
        if self.auto_rescue:
            if game_pid is None:
                raise RuntimeError("--auto-rescue requires a resolved game PID; use --pid if automatic binding is unavailable")
            self.rescue_bridge = FridaSocketBridge(game_pid, server_port, announce=True)

        # v30 passive correlation learner.  It NEVER transmits packets.
        self.learn_replies = learn_replies
        self.correlation = None
        if self.learn_replies:
            self.correlation = CorrelationLearner(
                log_path=learn_log,
                summary_path=learn_summary,
                window=learn_window,
                burst_gap=learn_burst_gap,
                min_support=learn_confirm,
                min_score=learn_score,
                samples_per_pair=learn_samples,
                checkpoint_seconds=learn_checkpoint,
                include_battle=learn_include_battle,
                cadence_min_period=learn_cadence_min,
                cadence_bin=learn_cadence_bin,
                announce=True,
            )
            print(
                f"[CORR] v30 passive correlation learner enabled; events={os.path.abspath(learn_log)}; "
                f"summary={os.path.abspath(learn_summary)}; no packets will be sent"
            )

        self.encounter = None
        if encounter_enabled:
            self.encounter = EncounterRecorder(
                log_path=encounter_log,
                summary_path=encounter_summary,
                freeze_dir=encounter_freeze_dir,
                pre_seconds=encounter_pre,
                post_seconds=encounter_tail,
                stall_seconds=encounter_stall,
                route_stall=encounter_route_stall,
                route_freeze=encounter_route_freeze,
                log_tcp=encounter_log_tcp,
                announce=True,
                l2_key=self.l2_key,
                auto_rescue=self.auto_rescue,
                rescue_bridge=self.rescue_bridge,
                rescue_action=rescue_action,
                rescue_timeout=rescue_timeout,
                rescue_verify_seconds=rescue_verify_seconds,
                rescue_baseline_path=rescue_baseline,
                rescue_min_support=rescue_min_support,
                rescue_min_purity=rescue_min_purity,
                rescue_socket_max_age=rescue_socket_max_age,
                rescue_max_attempts=rescue_max_attempts,
            )

    def on_payload(self, payload_len: int, **meta):
        self.packets += 1
        if self.encounter is not None:
            self.encounter.on_payload(payload_len, **meta)

    def _flow_local_port(self, msg: ProtocolMessage) -> int:
        return msg.sport if msg.dport == self.server_port else msg.dport

    def _probe_score(self, msg: ProtocolMessage) -> int:
        if not self.account or not msg.fields:
            return 0
        vals = []
        for field in msg.fields[:6]:
            v = deint(field, self.l2_key)
            if v is not None:
                vals.append(v)
        small = sum(1 for v in vals if -100000 <= v <= 100000)
        if len(vals) >= 3 and small >= 3:
            return 6
        if len(vals) >= 2 and small >= 2:
            return 2
        if small >= 1:
            return 1
        return 0

    def _accept_flow(self, msg: ProtocolMessage) -> bool:
        lp = self._flow_local_port(msg)
        if self.local_port is not None:
            return lp == self.local_port
        if self.auto_bound_port is not None:
            return lp == self.auto_bound_port

        score = self._probe_score(msg)
        if score:
            self.flow_scores[lp] += score
        if self.flow_scores[lp] >= 6:
            self.auto_bound_port = lp
            return True
        return False

    @staticmethod
    def _is_kn(code: str) -> bool:
        return (
            isinstance(code, str)
            and len(code) == 2
            and code[0] == "K"
            and code[1] in "0123456789ABCDEF"
        )

    @classmethod
    def _match_pattern(cls, codes, pattern) -> bool:
        if len(codes) < len(pattern):
            return False
        tail = codes[-len(pattern):]
        for got, exp in zip(tail, pattern):
            if exp == "Kn":
                if not cls._is_kn(got):
                    return False
            elif got != exp:
                return False
        return True

    @staticmethod
    def _native_code(text: str) -> Optional[str]:
        """Return only prefixes we have actually identified as protocol commands.

        Do NOT treat an arbitrary two-character string as a command.  The v10
        rule did that and could turn ordinary payload text such as ``hg`` into
        a fake stream opcode.
        """
        if not text:
            return None
        head = text.split("|", 1)[0]
        if head in {"BP", "BC", "BA", "BH", "BY", "BT", "BE"}:
            return head
        if len(head) == 2 and head[0] == "K" and head[1] in "0123456789ABCDEF":
            return head
        if head == "H":
            return "H0"
        if head == "W":
            return "W0"
        return None

    @staticmethod
    def _base36_fid(fid: str) -> str:
        """Stable two-character fallback for unknown numeric fid values."""
        try:
            n = int(fid)
        except ValueError:
            return "??"
        chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        n %= 36 * 36
        return chars[(n // 36) % 36] + chars[n % 36]

    def _code_for_message(self, msg: ProtocolMessage, decoded_values) -> str:
        # Prefer a native L2 command prefix whenever one exists.
        for kind, value in decoded_values:
            if kind == "str" and isinstance(value, str):
                code = self._native_code(value)
                if code:
                    return code

        # Display-layer mappings for known outer protocol messages.
        # fid=1 分流：
        # gcgc... 字符串 -> M1
        # fid=1 纯整数状态包 -> S1（避免误触发 M0 连续等待）
        # 其他 fid=1 未知文本 -> M0
        if msg.fid == "1":
            for kind, value in decoded_values:
                if (
                    kind == "str"
                    and isinstance(value, str)
                    and value.startswith("gcgc")
                ):
                    return "M1"

            if decoded_values and all(kind == "int" for kind, _ in decoded_values):
                return "S1"

            return "M0"
        if msg.fid == "42":
            return "P0"   # position/object state update

        # Unknown messages still receive a deterministic 2-char code so that
        # every accepted L2 message occupies exactly one slot in the stream.
        return self._base36_fid(msg.fid)

    def _emit_code(self, code: str) -> None:
        print(f"{code}|", end="", flush=True)
        self.stream_started = True

        # Keep a wider rolling window.  Some captures insert outer-state codes
        # between battle semantic opcodes; an 8-code tail was too brittle.
        self.recent_codes.append(code)
        if len(self.recent_codes) > 64:
            self.recent_codes.pop(0)

        # ---- round lifecycle markers -----------------------------------
        # Live L2 captures establish H as round start and W as round end.
        # These are deliberately DISPLAY markers only.  They must not change
        # self.in_battle, because one battle contains many H/W round pairs.
        if code == "H0":
            print(Fore.RED + "※" + Style.RESET_ALL + "|", end="", flush=True)
        elif code == "W0":
            print("★|", end="", flush=True)

        # Track distance/activity since the last accepted battle-init.  M1 is
        # the stable gcgc... field packet in the supplied --fields capture;
        # H0/W0/P0 are field/menu activity.  None is a result marker by itself.
        if self.codes_since_battle_init < 10**9:
            self.codes_since_battle_init += 1
        if code in {"M1", "H0", "W0", "P0", "08", "0H", "1L", "1S", "2F"}:
            self.scene_activity_since_init += 1

        # ---- battle entry / round init ---------------------------------
        # Strong signature remains BP|BC|BA.  Accept it when a Kx opcode was
        # seen shortly before BP (normally immediately before it, but a few
        # state packets may be interleaved).  This avoids missing later fights
        # while still being much stricter than treating every BA as entry.
        if code == "BP":
            prefix = self.recent_codes[:-1]
            self.battle_start_pending = 3 if any(self._is_kn(x) for x in prefix[-5:]) else 0
        elif (
            code == "BC"
            and not self.in_battle
            and "BE" in self.recent_codes[-12:-1]
        ):
            # 2026-10-03 live sequence: rescue -> BE -> map packets -> BC -> BA,
            # with no BP for the immediately re-entered fight.  The explicit BE
            # makes this BC a safe missing-BP restart anchor.
            self.battle_start_pending = 2
        elif self.battle_start_pending == 3:
            if code == "BC":
                self.battle_start_pending = 2
            elif code not in {"H0", "W0", "M0", "M1", "S1", "P0"}:
                self.battle_start_pending = 0
        elif self.battle_start_pending == 2:
            if code == "BA":
                # BP|BC|BA can be repeated several times during the same
                # battle transition.  Emit the external battle-start marker
                # only on the false -> true state transition; otherwise a
                # downstream consumer sees several fake battle starts.
                # Normal case: false -> true.  Recovery case: if an older
                # battle got stuck True but we have since seen a substantial
                # field/menu phase, this fresh init belongs to a new battle.
                # Re-emit ※ so downstream state is resynchronised.
                stale_battle = (
                    self.in_battle
                    and self.codes_since_battle_init >= 24
                    and self.scene_activity_since_init >= 8
                )
                if (not self.in_battle) or stale_battle:
                    print(Fore.RED + "※" + Style.RESET_ALL + "|", end="", flush=True)
                    self.in_battle = True
                    self.escape_armed = False
                    self.battle_end_pending = 0
                    self.battle_end_kn_count = 0
                    self.result_marker_locked = False
                # Whether this was a repeated round/state init or a recovered
                # new battle, start measuring from this confirmed init again.
                self.codes_since_battle_init = 0
                self.scene_activity_since_init = 0
                self.battle_start_pending = 0
            elif code not in {"H0", "W0", "M0", "M1", "S1", "P0"}:
                self.battle_start_pending = 0

        # Arm escape detection after the observed escape operation prefix.
        np = len(self.BATTLE_ESCAPE_PREFIX)
        if (
            len(self.recent_codes) >= np
            and tuple(self.recent_codes[-np:]) == self.BATTLE_ESCAPE_PREFIX
        ):
            self.escape_armed = True

        # ---- battle completion ----------------------------------------
        # BE is the server's explicit end-of-battle semantic marker.  v3 only
        # inferred completion from 2T/1R/1A/Kx tails; the 2026-10-03 rescue
        # capture ended with 1R/1A/Kx/02/BE (no 2T), leaving in_battle stuck
        # True and causing the immediately following BC->BA encounter to be
        # swallowed.  Treat BE as authoritative.
        if code == "BE" and self.in_battle:
            marker = "☆" if self.escape_armed else "★"
            print(marker + "|", end="", flush=True)
            self.in_battle = False
            self.result_marker_locked = True
            self.escape_armed = False
            self.battle_end_pending = 0
            self.battle_end_kn_count = 0
            return

        # NOTE from live L2 captures:
        # M1|08 and repeated H0|W0 pairs occur during an active battle too.
        # Therefore they must NOT be used as a battle-end signal.  Only the
        # stronger semantic result signatures below are allowed to emit ★/☆.
        # The stable semantic anchor in the supplied captures is
        # 2T|1R|1A followed by Kx result packets.  Older code required one of
        # several exact full tails, so one inserted/missing packet left
        # in_battle stuck forever and made all later detections fail.
        if code == "2T" and self.in_battle and not self.result_marker_locked:
            self.battle_end_pending = 3
            self.battle_end_kn_count = 0
        elif self.battle_end_pending == 3:
            if code == "1R":
                self.battle_end_pending = 2
            elif code not in {"H0", "W0", "M0", "M1", "S1", "P0", "0C"}:
                self.battle_end_pending = 0
        elif self.battle_end_pending == 2:
            if code == "1A":
                self.battle_end_pending = 1
                self.battle_end_kn_count = 0
            elif code not in {"H0", "W0", "M0", "M1", "S1", "P0"}:
                self.battle_end_pending = 0
        elif self.battle_end_pending == 1:
            if self._is_kn(code):
                self.battle_end_kn_count += 1
                if self.battle_end_kn_count >= 2:
                    # Even if an earlier entry marker was missed, this anchor
                    # is strong enough to resynchronise the state machine.
                    marker = "☆" if self.escape_armed else "★"
                    print(marker + "|", end="", flush=True)
                    self.in_battle = False
                    self.result_marker_locked = True
                    self.escape_armed = False
                    self.battle_end_pending = 0
                    self.battle_end_kn_count = 0
                    return
            elif code == "02" and self.battle_end_kn_count >= 1:
                # Current server commonly sends exactly one Kx result packet
                # before fid=2/02.  The anchored chain 2T->1R->1A->Kx->02 is
                # sufficient to declare battle completion; waiting for a second
                # Kx leaves in_battle stuck for ~60s until the client force-exits.
                marker = "☆" if self.escape_armed else "★"
                print(marker + "|", end="", flush=True)
                self.in_battle = False
                self.result_marker_locked = True
                self.escape_armed = False
                self.battle_end_pending = 0
                self.battle_end_kn_count = 0
                return
            elif code in {"H0", "W0", "M0", "M1", "S1", "P0"}:
                pass
            else:
                self.battle_end_pending = 0
                self.battle_end_kn_count = 0

        # Keep legacy signatures as compatibility fallbacks for captures that
        # use the older 13/1A or 1A/1A/11/1W forms.  They are now allowed to
        # resynchronise even when battle entry was missed.
        for pattern in (
            self.BATTLE_END_PATTERN_D,
            self.BATTLE_END_PATTERN_A,
            self.BATTLE_END_PATTERN_C,
            self.BATTLE_END_PATTERN_B,
        ):
            if (
                self.in_battle
                and not self.result_marker_locked
                and self._match_pattern(self.recent_codes, pattern)
            ):
                print("★|", end="", flush=True)
                self.in_battle = False
                self.result_marker_locked = True
                self.escape_armed = False
                self.battle_end_pending = 0
                self.battle_end_kn_count = 0
                return

        # Legacy escape-tail fallback.
        for escape_tail in (self.BATTLE_ESCAPE_TAIL, self.BATTLE_ESCAPE_TAIL_V2):
            if (
                self.in_battle
                and not self.result_marker_locked
                and self.escape_armed
                and self._match_pattern(self.recent_codes, escape_tail)
            ):
                print("☆|", end="", flush=True)
                self.in_battle = False
                self.result_marker_locked = True
                self.escape_armed = False
                self.battle_end_pending = 0
                self.battle_end_kn_count = 0
                return

    def _debug_message(self, msg: ProtocolMessage, decoded_values) -> None:
        """Optional verbose detail; only used when --fields or --raw is supplied."""
        if not (self.show_fields or self.show_raw):
            return
        print()  # leave the compact stream line before verbose diagnostics
        print(f"[DEBUG] {msg.direction} fid={msg.fid}")
        if self.show_fields and msg.fields:
            rendered = " | ".join(f"[{i}]={_display_bytes(v)}" for i, v in enumerate(msg.fields))
            print(f"    L1 fields: {rendered}")
        if decoded_values:
            print("    L2 typed : " + " | ".join(f"[{i}]={value}" for i, (_, value) in enumerate(decoded_values)))
        if self.show_raw:
            print(f"    L1 decoded: {_display_bytes(msg.decoded)}")
        print("[STREAM] ", end="", flush=True)

    def close(self) -> None:
        if self.encounter is not None:
            self.encounter.close()
        if self.correlation is not None:
            self.correlation.close()

    def on_message(self, msg: ProtocolMessage):
        if not self._accept_flow(msg):
            return

        self.messages += 1
        decoded_values = []
        if self.account and msg.fields:
            for v in msg.fields:
                kind, value, _, _ = decode_typed_field(v, self.l2_key)
                decoded_values.append((kind, value))

        code = self._code_for_message(msg, decoded_values)
        battle_before = self.in_battle
        # Update battle state first, then feed both learners.  Correlation may
        # still exclude battle traffic; EncounterRecorder never does once the
        # encounter transition has started.
        self._emit_code(code)
        rec = CorrelationLearner.message_record(msg, code, decoded_values)
        if self.correlation is not None:
            self.correlation.observe_record(rec, in_battle=self.in_battle)
        if self.encounter is not None:
            self.encounter.observe(
                rec,
                battle_before=battle_before,
                battle_after=self.in_battle,
                escape_armed=self.escape_armed,
            )
        self._debug_message(msg, decoded_values)


class PcapngTail:
    SHB = 0x0A0D0D0A
    IDB = 0x00000001
    EPB = 0x00000006

    def __init__(self, path: str, port: int, sink):
        self.path = os.path.abspath(path)
        self.port = port
        self.sink = sink
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.endian = "<"
        self.ifaces: Dict[int, dict] = {}
        self.linktype_warned = set()
        self.streams = LiveTCPStreamDecoder()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._loop, name="pcapng-tail", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2.0)

    def _loop(self) -> None:
        while not self.stop_event.is_set() and not os.path.exists(self.path):
            time.sleep(0.03)
        if self.stop_event.is_set():
            return

        pos = 0
        buf = bytearray()
        f = None
        while not self.stop_event.is_set() and f is None:
            try:
                f = open(self.path, "rb", buffering=0)
            except (PermissionError, OSError):
                time.sleep(0.05)
        if f is None:
            return

        try:
            while not self.stop_event.is_set():
                f.seek(pos)
                chunk = f.read(1024 * 1024)
                if chunk:
                    buf.extend(chunk)
                    pos += len(chunk)
                    self._consume(buf)
                else:
                    time.sleep(0.02)
        finally:
            f.close()

    def _consume(self, buf: bytearray) -> None:
        while len(buf) >= 12:
            raw_type = struct.unpack_from("<I", buf, 0)[0]
            if raw_type == self.SHB:
                bom = bytes(buf[8:12])
                if bom == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
                else:
                    return
                blen = struct.unpack_from(self.endian + "I", buf, 4)[0]
            else:
                blen = struct.unpack_from(self.endian + "I", buf, 4)[0]

            if blen < 12 or blen > 64 * 1024 * 1024:
                del buf[0]
                continue
            if len(buf) < blen:
                return

            block = bytes(buf[:blen])
            del buf[:blen]
            self._block(block)

    def _block(self, block: bytes) -> None:
        bt = struct.unpack_from(self.endian + "I", block, 0)[0]
        body = block[8:-4]

        if bt == self.SHB:
            self.ifaces.clear()
            return

        if bt == self.IDB:
            if len(body) < 8:
                return
            linktype = struct.unpack_from(self.endian + "H", body, 0)[0]
            idx = len(self.ifaces)
            info = {"linktype": linktype, "tsresol": 1e-6}
            p = 8
            while p + 4 <= len(body):
                code, ln = struct.unpack_from(self.endian + "HH", body, p)
                p += 4
                if code == 0:
                    break
                val = body[p : p + ln]
                p += (ln + 3) & ~3
                if code == 9 and val:
                    v = val[0]
                    info["tsresol"] = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
            self.ifaces[idx] = info
            return

        if bt != self.EPB or len(body) < 20:
            return

        ifid, th, tl, caplen, _origlen = struct.unpack_from(self.endian + "IIIII", body, 0)
        pkt = body[20 : 20 + caplen]
        iface = self.ifaces.get(ifid, {"linktype": 1, "tsresol": 1e-6})
        ts = ((th << 32) | tl) * float(iface.get("tsresol", 1e-6))
        parsed = self._parse_packet(pkt, int(iface.get("linktype", 1)))
        if not parsed:
            return

        src, dst, sport, dport, seq, ack, flags, payload = parsed
        direction = "C>S" if dport == self.port else "S>C"
        self.sink.on_payload(
            len(payload), ts=ts, direction=direction, seq=seq, ack=ack, flags=flags,
            sport=sport, dport=dport, src=src, dst=dst,
        )
        key = (src, sport, dst, dport)

        for dec in self.streams.feed(key, seq, payload):
            self.sink.on_message(
                ProtocolMessage(ts, direction, src, sport, dst, dport, dec)
            )

    def _parse_packet(self, pkt: bytes, linktype: int):
        # Same limitation as the original script: Ethernet / IPv4 / TCP.
        if linktype != 1:
            if linktype not in self.linktype_warned:
                self.linktype_warned.add(linktype)
                print(f"[WARN] linktype={linktype}; parser currently supports Ethernet (DLT=1) only")
            return None

        if len(pkt) < 14:
            return None
        et = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        for _ in range(2):
            if et in (0x8100, 0x88A8) and len(pkt) >= off + 4:
                et = struct.unpack("!H", pkt[off + 2 : off + 4])[0]
                off += 4
        if et != 0x0800 or len(pkt) < off + 20:
            return None

        ip = pkt[off:]
        ver = ip[0] >> 4
        ihl = (ip[0] & 0x0F) * 4
        if ver != 4 or ihl < 20 or len(ip) < ihl + 20 or ip[9] != 6:
            return None

        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        tcp = ip[ihl:]
        sport, dport, seq, ack, offflags = struct.unpack("!HHIIH", tcp[:14])
        if sport != self.port and dport != self.port:
            return None

        doff = ((offflags >> 12) & 0x0F) * 4
        if doff < 20 or len(tcp) < doff:
            return None

        payload = tcp[doff:]
        if not payload:
            return None
        flags = offflags & 0x01FF
        return src, dst, sport, dport, seq, ack, flags, payload


class DumpcapCapture:
    """Read dumpcap's pcapng stream directly from stdout.

    No capture file is created.  This also removes continuous disk writes from
    the hot path, which is preferable while the game is running.
    """

    def __init__(
        self,
        dumpcap: str,
        interface: Optional[str],
        port: int,
        sink,
        capture_filter: Optional[str] = None,
    ):
        self.dumpcap = dumpcap
        self.interface = interface
        self.port = port
        self.sink = sink
        self.capture_filter = capture_filter or f"tcp port {self.port}"
        self.proc: Optional[subprocess.Popen] = None
        # Reuse PcapngTail's block/TCP parser, but feed it bytes directly.
        self.parser = PcapngTail("<stdout>", port, sink)
        self.stop_event = threading.Event()
        self.reader_thread: Optional[threading.Thread] = None
        self.stderr_thread: Optional[threading.Thread] = None

    def _cmd(self) -> List[str]:
        cmd = [self.dumpcap]
        if self.interface:
            cmd += ["-i", self.interface]
        # '-' means pcapng goes to stdout instead of a file.
        cmd += ["-f", self.capture_filter, "-w", "-", "-q"]
        return cmd

    def start(self) -> None:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        flags |= getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
        self.proc = subprocess.Popen(
            self._cmd(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            creationflags=flags,
        )

        time.sleep(0.25)
        if self.proc.poll() is not None:
            err = b""
            if self.proc.stderr:
                try:
                    err = self.proc.stderr.read() or b""
                except Exception:
                    pass
            raise RuntimeError(
                f"dumpcap start failed code={self.proc.returncode}: "
                + err.decode("utf-8", "replace").strip()
            )

        self.reader_thread = threading.Thread(target=self._stdout_loop, daemon=True)
        self.stderr_thread = threading.Thread(target=self._stderr_loop, daemon=True)
        self.reader_thread.start()
        self.stderr_thread.start()
        print(f"[READY] interface={self.interface or 'auto'} port={self.port}  Ctrl+C stop")
        print("[STREAM] ", end="", flush=True)

    def _stdout_loop(self) -> None:
        if not self.proc or not self.proc.stdout:
            return
        buf = bytearray()
        while not self.stop_event.is_set():
            try:
                chunk = self.proc.stdout.read(65536)
            except Exception:
                break
            if not chunk:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.005)
                continue
            buf.extend(chunk)
            self.parser._consume(buf)

    def _stderr_loop(self) -> None:
        if not self.proc or not self.proc.stderr:
            return
        while not self.stop_event.is_set():
            try:
                raw = self.proc.stderr.readline()
            except Exception:
                break
            if not raw:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.02)
                continue
            line = raw.decode("utf-8", "replace").strip()
            if line and any(
                x in line.lower()
                for x in ("error", "failed", "permission", "access", "npcap", "invalid", "can't", "cannot")
            ):
                print(f"\n[dumpcap] {line}\n[STREAM] ", end="", flush=True)

    def stop(self) -> None:
        self.stop_event.set()
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self.reader_thread:
            self.reader_thread.join(timeout=1.0)
        if self.stderr_thread:
            self.stderr_thread.join(timeout=1.0)


# Windows process-handle APIs used to bind the selected STW instance to its game process.
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 0x00000002
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", wintypes.LPVOID),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]

if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessId.restype = wintypes.DWORD
    ntdll.NtQuerySystemInformation.argtypes = [
        wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
    ]
    ntdll.NtQuerySystemInformation.restype = wintypes.LONG
else:
    kernel32 = None
    ntdll = None

def list_game_pids(game_name: str = GAME_PROCESS_NAME):
    if psutil is None:
        raise RuntimeError("automatic process discovery requires psutil: pip install psutil")
    out = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info.get("name")
            if name and name.lower() == game_name.lower():
                out.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return sorted(out)

def get_stw_pids(stw_name: str = STW_PROCESS_NAME):
    if psutil is None:
        raise RuntimeError("automatic process discovery requires psutil: pip install psutil")
    pids = set()
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info.get("name")
            if name and name.lower() == stw_name.lower():
                pids.add(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return pids

def get_window_pid(hwnd):
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        return pid
    except Exception:
        return None

def find_script_window_stw_pid(stw_name: str = STW_PROCESS_NAME, window_text: str = SCRIPT_WINDOW_TEXT) -> int:
    if win32gui is None or win32process is None:
        raise RuntimeError("automatic STW window discovery requires pywin32: pip install pywin32")
    stw_pids = get_stw_pids(stw_name)
    if not stw_pids:
        raise RuntimeError(f"cannot find process {stw_name}")
    matches = []
    def callback(hwnd, _):
        try:
            pid = get_window_pid(hwnd)
            if pid not in stw_pids:
                return True
            title = win32gui.GetWindowText(hwnd).strip()
            if window_text in title:
                matches.append((hwnd, pid, title))
        except Exception:
            pass
        return True
    win32gui.EnumWindows(callback, None)
    if not matches:
        raise RuntimeError(f"cannot find a {stw_name} top-level window containing {window_text!r}")
    if len(matches) != 1:
        rows = ", ".join(f"PID={pid} TITLE={title!r}" for _hwnd, pid, title in matches)
        raise RuntimeError(f"found multiple {window_text!r} STW windows: {rows}")
    _hwnd, pid, title = matches[0]
    print(f"[STW] {title!r} -> {stw_name} PID={pid}")
    return pid

def _stw_open_process_targets(stw_pid: int):
    source = kernel32.OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, False, int(stw_pid)
    )
    if not source:
        return set()
    try:
        size = 1 << 20
        needed = wintypes.ULONG(0)
        buf = None
        while size <= (1 << 27):
            buf = ctypes.create_string_buffer(size)
            status = ntdll.NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, size, ctypes.byref(needed)
            )
            if (status & 0xFFFFFFFF) == STATUS_INFO_LENGTH_MISMATCH:
                size = max(size * 2, int(needed.value) + 0x10000)
                continue
            if status < 0:
                return set()
            break
        else:
            return set()

        ptr_size = ctypes.sizeof(ctypes.c_size_t)
        count = ctypes.c_size_t.from_buffer(buf, 0).value
        offset = ptr_size * 2
        entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
        current = kernel32.GetCurrentProcess()
        targets = set()
        for i in range(count):
            pos = offset + i * entry_size
            if pos + entry_size > len(buf):
                break
            e = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer(buf, pos)
            if int(e.UniqueProcessId) != int(stw_pid):
                continue
            dup = wintypes.HANDLE()
            ok = kernel32.DuplicateHandle(
                source, wintypes.HANDLE(e.HandleValue), current, ctypes.byref(dup),
                0, False, DUPLICATE_SAME_ACCESS
            )
            if not ok or not dup:
                continue
            try:
                pid = int(kernel32.GetProcessId(dup) or 0)
                if pid:
                    targets.add(pid)
            finally:
                kernel32.CloseHandle(dup)
        return targets
    finally:
        kernel32.CloseHandle(source)

def resolve_game_pid_for_stw(stw_pid: int, game_name: str = GAME_PROCESS_NAME) -> int:
    games = list_game_pids(game_name)
    if not games:
        raise RuntimeError(f"cannot find game process {game_name}")
    game_set = set(games)

    opened = _stw_open_process_targets(stw_pid) & game_set
    if len(opened) == 1:
        pid = next(iter(opened))
        print(f"[PROC] STW PID={stw_pid} -> process handle -> {game_name} PID={pid}")
        return pid
    if len(opened) > 1:
        print(f"[WARN] STW PID={stw_pid} holds multiple {game_name} handles: {sorted(opened)}")

    related = []
    for pid in games:
        try:
            gp = psutil.Process(pid)
            if gp.ppid() == stw_pid:
                related.append(pid)
                continue
            sp = psutil.Process(stw_pid)
            if sp.ppid() == pid:
                related.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    related = sorted(set(related))
    if len(related) == 1:
        pid = related[0]
        print(f"[PROC] STW PID={stw_pid} -> parent/child fallback -> {game_name} PID={pid}")
        return pid

    if len(games) == 1:
        pid = games[0]
        print(f"[PROC] only one {game_name} exists -> PID={pid}")
        return pid

    raise RuntimeError(
        f"multiple {game_name} processes exist ({games}), but STW PID={stw_pid} cannot uniquely bind one"
    )

def find_game_pid_from_stw(stw_name: str = STW_PROCESS_NAME, game_name: str = GAME_PROCESS_NAME) -> int:
    stw_pid = find_script_window_stw_pid(stw_name, SCRIPT_WINDOW_TEXT)
    return resolve_game_pid_for_stw(stw_pid, game_name)

def find_flow_for_pid(pid: int, server_port: int):
    if psutil is None:
        raise RuntimeError("--pid requires psutil: pip install psutil")

    proc = psutil.Process(int(pid))
    try:
        conns = proc.net_connections(kind="tcp")
    except AttributeError:
        conns = proc.connections(kind="tcp")

    flows = []
    for c in conns:
        if not c.laddr or not c.raddr:
            continue
        lip = getattr(c.laddr, "ip", c.laddr[0])
        lport = getattr(c.laddr, "port", c.laddr[1])
        rip = getattr(c.raddr, "ip", c.raddr[0])
        rport = getattr(c.raddr, "port", c.raddr[1])
        if int(rport) != int(server_port):
            continue
        status = str(getattr(c, "status", "")).upper()
        flows.append((str(lip), int(lport), str(rip), int(rport), status))

    established = [x for x in flows if "ESTABLISHED" in x[4]]
    use = established or flows
    uniq = {(x[0], x[1], x[2], x[3]): x for x in use}
    if not uniq:
        raise RuntimeError(f"PID={pid} currently has no remote TCP/{server_port} connection")
    if len(uniq) != 1:
        rows = ", ".join(f"{a}:{b}->{c}:{d}" for a, b, c, d in uniq)
        raise RuntimeError(f"PID={pid} has multiple TCP/{server_port} sessions: {rows}")

    lip, lport, rip, rport, _ = next(iter(uniq.values()))
    return lip, lport, rip, rport


def exact_bpf(flow) -> str:
    lip, lport, rip, rport = flow
    return (
        f"tcp and ((src host {lip} and src port {lport} and dst host {rip} and dst port {rport}) "
        f"or (src host {rip} and src port {rport} and dst host {lip} and dst port {lport}))"
    )


def list_interfaces(dumpcap: str) -> int:
    return subprocess.call([dumpcap, "-D"])


def build_args():
    p = argparse.ArgumentParser(description="SA realtime parser v31 - encounter freeze rescue + full recorder + passive correlation learner")
    p.add_argument("--dumpcap", default=DEFAULT_DUMPCAP_PATH, help="path to dumpcap.exe")
    p.add_argument("-i", "--interface", default=DEFAULT_INTERFACE, help="dumpcap interface number/name")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="game server TCP port")
    p.add_argument("--pid", type=int, help="optional game PID; overrides automatic STW binding")
    p.add_argument("--stw-name", default=STW_PROCESS_NAME, help=f"STW process name (default: {STW_PROCESS_NAME})")
    p.add_argument("--game-name", default=GAME_PROCESS_NAME, help=f"game process name (default: {GAME_PROCESS_NAME})")
    p.add_argument("--account", help='account; L2 key is derived automatically as account + "bing"; if omitted, CMD will prompt')
    p.add_argument("--local-port", type=int, help="optional client TCP port; useful when interface 10 has multiple 9065 sessions")
    p.add_argument("--fields", action="store_true", help="show L1 split fields (hidden by default)")
    p.add_argument("--raw", action="store_true", help="show full L1 decoded message (hidden by default)")
    p.add_argument("--learn-replies", "--correlate", dest="learn_replies", action="store_true", help="enable v30 passive correlation learner; NEVER sends packets")
    p.add_argument("--learn-log", default="correlation_learning.jsonl", help="compact JSONL containing only capped samples/state changes")
    p.add_argument("--learn-summary", default="correlation_summary.json", help="rolling aggregate correlation report (overwritten, stays small)")
    p.add_argument("--learn-window", type=float, default=2.0, help="maximum S>C -> C>S temporal window (default: 2.0s)")
    p.add_argument("--learn-burst-gap", type=float, default=0.050, help="server messages within this gap form one ambiguous burst (default: 0.050s)")
    p.add_argument("--learn-confirm", type=int, default=20, help="minimum support before correlation classification (default: 20)")
    p.add_argument("--learn-score", type=float, default=0.50, help="minimum score for STRONG after support/coverage/purity gates (default: 0.50)")
    p.add_argument("--learn-samples", type=int, default=3, help="full payload samples retained per correlation shape (default: 3)")
    p.add_argument("--learn-checkpoint", type=float, default=30.0, help="seconds between summary checkpoints (default: 30)")
    p.add_argument("--learn-include-battle", action="store_true", help="also use in-battle messages for temporal correlation (default: idle only)")
    p.add_argument("--learn-cadence-min", type=float, default=5.0, help="minimum period to report as cadence candidate (default: 5s)")
    p.add_argument("--learn-cadence-bin", type=float, default=0.25, help="cadence histogram bin width in seconds (default: 0.25)")
    p.add_argument("--no-encounter-recorder", action="store_true", help="disable v31 encounter black-box recorder (enabled by default)")
    p.add_argument("--encounter-log", default="encounter_learning.jsonl", help="decoded encounter-message log; TCP metadata stays in the in-memory freeze ring unless --encounter-log-tcp is used")
    p.add_argument("--encounter-summary", default="encounter_summary.json", help="rolling v31 encounter/reply-pair/rescue summary")
    p.add_argument("--encounter-freeze-dir", default="encounter_freezes", help="directory for automatic freeze snapshots")
    p.add_argument("--encounter-pre", type=float, default=8.0, help="seconds of pre-encounter decoded/TCP history retained (default: 8)")
    p.add_argument("--encounter-tail", type=float, default=5.0, help="seconds kept after battle exit (default: 5)")
    p.add_argument("--encounter-stall", type=float, default=3.0, help="silence threshold for pre-BA/route diagnostics (default: 3s)")
    p.add_argument("--no-route-stall", action="store_true", help="disable compact route-transition silence diagnostics")
    p.add_argument("--route-freeze", action="store_true", help="also write full freeze snapshots for route-transition silence (off by default; v28 behavior produced many false positives)")
    p.add_argument("--encounter-log-tcp", action="store_true", help="write every encounter TCP payload metadata record to JSONL; off by default because freeze snapshots already retain the TCP ring")
    p.add_argument("--auto-rescue", action="store_true", help="v31: after a confirmed BP/BC/BA stall with no client/server progress, send one learned E/W escape pair (or --rescue-action hw) through the game's own Winsock (requires Frida)")
    p.add_argument("--rescue-action", choices=("escape", "hw"), default="escape", help="action used for auto rescue: escape=E+W (default, matches normal auto-escape captures), hw=legacy H+W")
    p.add_argument("--rescue-timeout", type=float, default=1.5, help="seconds after entry BA to wait for either H/W or E/W before rescue evaluation (default: 1.5; supplied normal max ~1.16s)")
    p.add_argument("--rescue-verify", type=float, default=1.5, help="seconds after a rescue send before snapshotting no server progress (default: 1.5)")
    p.add_argument("--rescue-baseline", default="encounter_rescue_baseline.json", help="persistent BA-mask -> entry-response target model; seeded from the supplied 870 normal entries")
    p.add_argument("--rescue-min-support", type=int, default=5, help="minimum successful baseline observations before a mask can auto-rescue (default: 5)")
    p.add_argument("--rescue-min-purity", type=float, default=1.0, help="required dominant target ratio for H/W rescue; escape rescue accepts a supported valid dominant target (default: 1.0)")
    p.add_argument("--rescue-socket-max-age", type=float, default=120.0, help="maximum seconds since the Frida bridge last observed the game socket (default: 120)")
    p.add_argument("--rescue-max-attempts", type=int, default=1, help="maximum rescue sends per encounter (default: 1)")
    p.add_argument("--analyze-learning", metavar="PATH", help="offline-analyze a v25 reply_learning.jsonl or ZIP, then exit")
    p.add_argument("--analysis-output", default="correlation_analysis.json", help="offline analysis JSON output path")
    p.add_argument("--list-interfaces", action="store_true", help="run dumpcap -D and exit")
    return p.parse_args()


def main():
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    args = build_args()

    if args.auto_rescue and args.no_encounter_recorder:
        raise SystemExit("--auto-rescue requires the encounter recorder; remove --no-encounter-recorder")
    if args.rescue_min_purity < 0.0 or args.rescue_min_purity > 1.0:
        raise SystemExit("--rescue-min-purity must be between 0 and 1")

    if args.analyze_learning:
        analyze_learning_file(args.analyze_learning, args.analysis_output, args)
        return

    dumpcap = args.dumpcap if os.path.isfile(args.dumpcap) else shutil.which("dumpcap")
    if not dumpcap:
        raise SystemExit("dumpcap.exe not found; use --dumpcap to specify its path")

    if args.list_interfaces:
        raise SystemExit(list_interfaces(dumpcap))

    capture_filter = f"tcp port {args.port}"
    resolved_local_port = args.local_port

    # Binding priority:
    #   1) explicit --pid
    #   2) explicit --local-port (manual fallback)
    #   3) automatic 脚本制作 window -> STW0.30.exe -> bound sa_2903.exe discovery
    resolved_pid = args.pid
    # Auto-rescue needs a PID even when a manual local port was supplied,
    # because the Frida bridge must attach to the actual game process.
    if resolved_pid is None and (args.local_port is None or args.auto_rescue):
        resolved_pid = find_game_pid_from_stw(args.stw_name, args.game_name)

    if resolved_pid is not None:
        flow = find_flow_for_pid(resolved_pid, args.port)
        capture_filter = exact_bpf(flow)
        resolved_local_port = flow[1]
        print(f"[BIND] PID={resolved_pid}: {flow[0]}:{flow[1]} <-> {flow[2]}:{flow[3]}")
    elif args.local_port is not None:
        print(f"[BIND] manual local-port={args.local_port}, remote TCP/{args.port}")

    account = args.account
    if not account:
        try:
            account = input("Account (required for L2 decode): ").strip()
        except (EOFError, KeyboardInterrupt):
            account = ""
    if not account:
        raise SystemExit("account is required for layer-2 decode; use --account <account>")


    sink = ConsoleSink(
        show_fields=args.fields,
        show_raw=args.raw,
        account=account,
        local_port=resolved_local_port,
        server_port=args.port,
        learn_replies=args.learn_replies,
        learn_log=args.learn_log,
        learn_summary=args.learn_summary,
        learn_window=args.learn_window,
        learn_burst_gap=args.learn_burst_gap,
        learn_confirm=args.learn_confirm,
        learn_score=args.learn_score,
        learn_samples=args.learn_samples,
        learn_checkpoint=args.learn_checkpoint,
        learn_include_battle=args.learn_include_battle,
        learn_cadence_min=args.learn_cadence_min,
        learn_cadence_bin=args.learn_cadence_bin,
        encounter_enabled=not args.no_encounter_recorder,
        encounter_log=args.encounter_log,
        encounter_summary=args.encounter_summary,
        encounter_freeze_dir=args.encounter_freeze_dir,
        encounter_pre=args.encounter_pre,
        encounter_tail=args.encounter_tail,
        encounter_stall=args.encounter_stall,
        encounter_route_stall=not args.no_route_stall,
        encounter_route_freeze=args.route_freeze,
        encounter_log_tcp=args.encounter_log_tcp,
        game_pid=resolved_pid,
        auto_rescue=args.auto_rescue,
        rescue_action=args.rescue_action,
        rescue_timeout=args.rescue_timeout,
        rescue_verify_seconds=args.rescue_verify,
        rescue_baseline=args.rescue_baseline,
        rescue_min_support=args.rescue_min_support,
        rescue_min_purity=args.rescue_min_purity,
        rescue_socket_max_age=args.rescue_socket_max_age,
        rescue_max_attempts=args.rescue_max_attempts,
    )
    cap = DumpcapCapture(
        dumpcap=dumpcap,
        interface=args.interface,
        port=args.port,
        sink=sink,
        capture_filter=capture_filter,
    )

    try:
        cap.start()
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()
        sink.close()
        print(f"\n[STOP] messages={sink.messages}, TCP-payloads={sink.packets}; no capture file created")


if __name__ == "__main__":
    main()
