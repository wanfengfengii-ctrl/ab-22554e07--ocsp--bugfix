"""Minimal DER reader/encoder helpers.

Used for the parts of X.509/PKIX structures that the cryptography library
does not expose (e.g. enumerating CRL revokedCertificates entries).  Only
definite-length, DER-encoded input is accepted.
"""
from __future__ import annotations

from datetime import datetime, timezone


def read_tlv(data: bytes, pos: int):
    """Read one TLV; returns (tag, content_start, content_end)."""
    if pos >= len(data):
        raise ValueError("truncated DER: expected tag")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tags are not supported")
    pos += 1
    if pos >= len(data):
        raise ValueError("truncated DER: expected length")
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0:
            raise ValueError("indefinite length is not DER")
        if pos + n > len(data):
            raise ValueError("truncated DER: length bytes")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER: content")
    return tag, pos, end


def encode_tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        hdr = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        hdr = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + hdr + content


def parse_der_time(data: bytes, pos: int):
    """Parse a UTCTime/GeneralizedTime TLV; returns (datetime, next_pos)."""
    tag, start, end = read_tlv(data, pos)
    raw = data[start:end]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid time encoding") from exc
    if not text.endswith("Z"):
        raise ValueError("only Zulu times are supported")
    text = text[:-1]
    if tag == 0x17:  # UTCTime
        if len(text) != 10 and len(text) != 12:
            raise ValueError("bad UTCTime length")
        fmt = "%y%m%d%H%M%S" if len(text) == 12 else "%y%m%d%H%M"
        dt = datetime.strptime(text, fmt)
        year = dt.year
        year = year - 100 if year >= 2050 else year
        dt = dt.replace(year=year)
    elif tag == 0x18:  # GeneralizedTime
        fmt = "%Y%m%d%H%M%S" if len(text) == 14 else "%Y%m%d%H%M"
        dt = datetime.strptime(text, fmt)
    else:
        raise ValueError(f"expected time tag, got 0x{tag:02x}")
    return dt.replace(tzinfo=timezone.utc), end


def iter_crl_entries(der: bytes):
    """Yield (serial:int, revocation_date:datetime, extensions_tlv:bytes|None)
    for each revokedCertificates entry of a DER CRL.

    *extensions_tlv* is the raw TLV bytes of the Extensions SEQUENCE when
    present (tag included).
    """
    tag, tbs_start, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("CRL must be a SEQUENCE")
    tag, tbs_content, tbs_end = read_tlv(der, tbs_start)
    if tag != 0x30:
        raise ValueError("tbsCertList must be a SEQUENCE")
    pos = tbs_content
    # optional version (a bare INTEGER in TBSCertList, unlike certificates)
    tag, start, end = read_tlv(der, pos)
    if tag == 0x02:
        pos = end
    # signature AlgorithmIdentifier
    _, _, end = read_tlv(der, pos)
    pos = end
    # issuer Name
    _, _, end = read_tlv(der, pos)
    pos = end
    # thisUpdate
    _, pos = parse_der_time(der, pos)
    # optional nextUpdate
    tag = der[pos]
    if tag in (0x17, 0x18):
        _, pos = parse_der_time(der, pos)
    if pos >= tbs_end:
        return
    tag, start, end = read_tlv(der, pos)
    if tag != 0x30:
        return  # no revokedCertificates
    pos = start
    while pos < end:
        etag, estart, eend = read_tlv(der, pos)
        if etag != 0x30:
            raise ValueError("revoked certificate entry must be a SEQUENCE")
        epos = estart
        stag, sstart, send = read_tlv(der, epos)
        if stag != 0x02:
            raise ValueError("entry serial must be an INTEGER")
        serial = int.from_bytes(der[sstart:send], "big", signed=False)
        rev_date, epos = parse_der_time(der, send)
        ext_tlv = None
        if epos < eend:
            xtag, xstart, xend = read_tlv(der, epos)
            if xtag != 0x30:
                raise ValueError("entry extensions must be a SEQUENCE")
            ext_tlv = der[epos:xend]
        yield serial, rev_date, ext_tlv
        pos = eend


_OID_REASON_CODE = bytes.fromhex("551d15")       # 2.5.29.21 (content bytes)
_OID_CERT_ISSUER = bytes.fromhex("551d1d")       # 2.5.29.29
_OID_INVALIDITY_DATE = bytes.fromhex("551d18")   # 2.5.29.24


def iter_extensions(ext_tlv: bytes):
    """Yield (oid_bytes, critical:bool, value:bytes) for an Extensions TLV."""
    _, start, end = read_tlv(ext_tlv, 0)
    pos = start
    while pos < end:
        _, es, ee = read_tlv(ext_tlv, pos)
        epos = es
        otag, os_, oe = read_tlv(ext_tlv, epos)
        if otag != 0x06:
            raise ValueError("extension id must be an OID")
        oid = ext_tlv[os_:oe]
        epos = oe
        critical = False
        if ext_tlv[epos] == 0x01:
            _, cs, ce = read_tlv(ext_tlv, epos)
            critical = ext_tlv[cs] != 0
            epos = ce
        vtag, vs, ve = read_tlv(ext_tlv, epos)
        if vtag != 0x04:
            raise ValueError("extension value must be an OCTET STRING")
        yield oid, critical, ext_tlv[vs:ve]
        pos = ee


def parse_reason_code(value: bytes) -> int:
    tag, start, end = read_tlv(value, 0)
    if tag != 0x0A or end - start != 1:
        raise ValueError("bad reasonCode")
    return value[start]


def _read_base128(data: bytes, pos: int):
    value = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated base-128 integer")
        b = data[pos]
        pos += 1
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            return value, pos


def der_to_oid(tlv: bytes):
    """Decode an OID TLV (tag included) to (dotted_string, next_pos)."""
    tag, start, end = read_tlv(tlv, 0)
    if tag != 0x06:
        raise ValueError("expected OID")
    first, pos = _read_base128(tlv, start)
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    while pos < end:
        arc, pos = _read_base128(tlv, pos)
        arcs.append(arc)
    return ".".join(str(a) for a in arcs), end


def oid_to_der(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    if len(parts) < 2 or parts[0] > 2 or parts[1] > 39 and parts[0] < 2:
        raise ValueError(f"invalid OID {dotted!r}")
    out = bytearray()
    first = 40 * parts[0] + parts[1]
    stack = [first & 0x7F]
    first >>= 7
    while first:
        stack.append(0x80 | (first & 0x7F))
        first >>= 7
    out += bytes(reversed(stack))
    for arc in parts[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(stack))
    return encode_tlv(0x06, bytes(out))


def parse_policy_mappings(extn_value: bytes):
    """PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy OID,
    subjectDomainPolicy OID }.  Returns a tuple of (issuer, subject) dotted
    OID pairs."""
    tag, start, end = read_tlv(extn_value, 0)
    if tag != 0x30:
        raise ValueError("policyMappings must be a SEQUENCE")
    out = []
    pos = start
    while pos < end:
        tag, es, ee = read_tlv(extn_value, pos)
        if tag != 0x30:
            raise ValueError("policyMapping must be a SEQUENCE")
        inner = extn_value[es:ee]
        issuer_oid, p2 = der_to_oid(inner)
        subject_oid, p3 = der_to_oid(inner[p2:])
        if p2 + p3 != len(inner):
            raise ValueError("policyMapping must contain exactly two OIDs")
        out.append((issuer_oid, subject_oid))
        pos = ee
    return tuple(out)


_HASH_OIDS = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.3.14.3.2.26": "sha1",
}


def extract_ocsp_signature_algorithm(der: bytes):
    """Pull the signatureAlgorithm OID and raw params out of a DER OCSP
    response (cryptography does not expose PSS params for OCSP)."""
    _, c, _ = read_tlv(der, 0)
    _, _, e = read_tlv(der, c)              # responseStatus
    tag, s, _ = read_tlv(der, e)            # [0] EXPLICIT ResponseBytes
    if tag != 0xA0:
        raise ValueError("missing responseBytes")
    _, s2, _ = read_tlv(der, s)             # SEQUENCE ResponseBytes
    _, _, e3 = read_tlv(der, s2)            # responseType OID
    _, bs, be = read_tlv(der, e3)           # response OCTET STRING
    basic = der[bs:be]
    _, c2, _ = read_tlv(basic, 0)
    _, _, e4 = read_tlv(basic, c2)          # tbsResponseData
    tag, as_, ae = read_tlv(basic, e4)      # signatureAlgorithm
    if tag != 0x30:
        raise ValueError("missing signatureAlgorithm")
    alg_tlv = basic[e4:ae]
    _, cs, _ = read_tlv(alg_tlv, 0)
    oid, pos = der_to_oid(alg_tlv[cs:])
    params = alg_tlv[cs + pos :] if cs + pos < len(alg_tlv) else None
    return oid, params


def pss_params_hash_name(params_tlv: bytes | None):
    """Extract the hash algorithm name from RSASSA-PSS params (None for the
    PSS defaults, which are SHA-1 and therefore out of profile)."""
    if not params_tlv:
        return None
    tag, start, end = read_tlv(params_tlv, 0)
    if tag != 0x30:
        return None
    pos = start
    while pos < end:
        tag, cs, ce = read_tlv(params_tlv, pos)
        if tag == 0xA0:  # hashAlgorithm [0]
            _, is_, _ = read_tlv(params_tlv, cs)
            oid, _ = der_to_oid(params_tlv[is_:ce])
            return _HASH_OIDS.get(oid)
        pos = ce
    return None  # default hashAlgorithm is sha1
