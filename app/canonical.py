"""Canonical JSON + hashing + time helpers.

Canonical JSON rules (stable across processes, versions and machines):
  * UTF-8, no insignificant whitespace.
  * Object keys sorted by Unicode code point.
  * Strings escaped JSON.stringify-style (short escapes for \\b \\f \\n \\r \\t,
    \\u00XX for other control characters, everything else raw UTF-8).
  * Integers only (no floats, no exponents).  Booleans true/false, null.
  * Duplicate object keys are rejected on parse.

All digests are SHA-256 rendered as lowercase hex.  All timestamps are
RFC 3339 normalized to UTC ``YYYY-MM-DDTHH:MM:SSZ`` (fractional seconds are
preserved, trimmed of trailing zeros, when present).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _dump(obj, out: list) -> None:
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, int):
        out.append(str(obj))
    elif isinstance(obj, str):
        out.append(_escape_string(obj))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, item in enumerate(obj):
            if i:
                out.append(",")
            _dump(item, out)
        out.append("]")
    elif isinstance(obj, dict):
        out.append("{")
        for i, key in enumerate(sorted(obj.keys())):
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            if i:
                out.append(",")
            _dump(key, out)
            out.append(":")
            _dump(obj[key], out)
        out.append("}")
    else:
        raise TypeError(f"not canonical-JSON serializable: {type(obj)!r}")


def dumps(obj) -> bytes:
    """Serialize *obj* to canonical JSON bytes."""
    out: list = []
    _dump(obj, out)
    return "".join(out).encode("utf-8")


def _no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate object key: {k!r}")
        obj[k] = v
    return obj


def _no_surrogates(obj):
    if isinstance(obj, str):
        for ch in obj:
            o = ord(ch)
            if 0xD800 <= o <= 0xDFFF:
                raise ValueError("lone surrogates are not allowed in strings")
    elif isinstance(obj, list):
        for item in obj:
            _no_surrogates(item)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _no_surrogates(k)
            _no_surrogates(v)


def loads(data: bytes):
    """Parse JSON, rejecting duplicate keys, non-finite numbers, floats and
    lone surrogates."""
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data

    def _reject_float(x):
        raise ValueError("floating point numbers are not allowed")

    obj = json.loads(
        text,
        object_pairs_hook=_no_duplicates,
        parse_float=_reject_float,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"invalid constant {x}")),
    )
    _no_surrogates(obj)
    return obj


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj) -> str:
    return sha256_hex(dumps(obj))


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64 string")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"invalid base64: {exc}") from exc


_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def parse_time(value) -> datetime:
    """Parse an RFC 3339 timestamp; the offset (or Z) is mandatory."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    m = _RFC3339_RE.match(value)
    if not m:
        raise ValueError(f"invalid RFC 3339 timestamp: {value!r}")
    year, mon, day, hh, mm, ss = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7)
    micro = 0
    if frac:
        digits = (frac[1:] + "000000")[:6]
        micro = int(digits)
    offset = m.group(8)
    if offset == "Z":
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        oh, om = int(offset[1:3]), int(offset[4:6])
        if oh > 23 or om > 59:
            raise ValueError(f"invalid UTC offset: {value!r}")
        from datetime import timedelta

        tz = timezone(sign * timedelta(hours=oh, minutes=om))
    try:
        dt = datetime(year, mon, day, hh, mm, ss, micro, tzinfo=tz)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value!r} ({exc})") from exc
    return dt.astimezone(timezone.utc)


def canon_time(dt: datetime) -> str:
    """Render an aware datetime in canonical UTC form."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime is not allowed")
    dt = dt.astimezone(timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        base += (".%06d" % dt.microsecond).rstrip("0")
    return base + "Z"


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def is_fingerprint(value) -> bool:
    return isinstance(value, str) and bool(_HEX64_RE.match(value))
