"""
features.py - Entropy helpers and FlowAnalysis -> NumPy feature vector.

Vector layout (np.float32, 1-D). Indices 0-14 follow the spec order; 15-19 are
extra posture features appended at the end so the spec prefix stays stable.

    0  duration_s              log1p-scaled when normalize=True
    1  orig_bytes              log1p
    2  resp_bytes              log1p
    3  sni_length
    4  sni_entropy             Shannon bits/char
    5  ja3_num                 [0,1) bounded hash, or ja3_e0..e{k-1} embedding
    6  ja3s_num                idem
    7  cert_lifespan_days      log1p
    8  cert_self_signed        0/1
    9  cert_pubkey_bits
   10  cert_subject_entropy    of subject CN (full DN if no CN)
   11  cert_issuer_entropy     of issuer CN (full DN if no CN)
   12  punycode_present        'xn--' in SNI, cert CN or SANs
   13  email_has_attachment    0/1
   14  email_subject_entropy   max over transactions in the flow
   15  tls_version             0=none, 2.0=SSLv2 ... 1.3=TLS1.3 (see _TLS_NUM)
   16  tls_observed            0/1
   17  cert_observed           0/1  (0 for TLS 1.3 / plaintext)
   18  cleartext_auth          0/1  AUTH/LOGIN/USER/PASS seen unencrypted
   19  starttls                0/1

Missing values (no TLS, no cert, no SNI ...) are encoded as MISSING = -1.0 and
the *_observed flags let a model tell "absent" apart from "zero".
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import Dict, List, Optional, Sequence

import numpy as np

from dissector import FlowAnalysis

MISSING = -1.0

_TLS_NUM = {"SSLv2": 0.2, "SSLv3": 0.3, "TLSv10": 1.0, "TLSv11": 1.1,
            "TLSv12": 1.2, "TLSv13": 1.3}

BASE_FEATURES = [
    "duration_s", "orig_bytes", "resp_bytes", "sni_length", "sni_entropy",
    "ja3_num", "ja3s_num", "cert_lifespan_days", "cert_self_signed",
    "cert_pubkey_bits", "cert_subject_entropy", "cert_issuer_entropy",
    "punycode_present", "email_has_attachment", "email_subject_entropy",
    "tls_version", "tls_observed", "cert_observed", "cleartext_auth", "starttls",
]
LOG_SCALED = {"duration_s", "orig_bytes", "resp_bytes", "cert_lifespan_days"}


# --------------------------------------------------------------------------- #
# Primitive transforms
# --------------------------------------------------------------------------- #
def shannon_entropy(s: Optional[str]) -> float:
    """Shannon entropy in bits per symbol over the UTF-8 byte distribution."""
    if not s:
        return 0.0
    data = s.encode("utf-8", "replace") if isinstance(s, str) else bytes(s)
    n = len(data)
    return float(-sum((c / n) * math.log2(c / n) for c in Counter(data).values()))


def hash_to_unit(h: Optional[str]) -> float:
    """Map a JA3/JA3S MD5 hex digest to a stable scalar in [0, 1).
    Equal fingerprints -> equal values; distance carries no meaning, so this
    suits tree models. Use embeddings for linear/NN models."""
    if not h:
        return MISSING
    try:
        return int(h[:8], 16) / 2**32
    except ValueError:
        return int(hashlib.md5(h.encode()).hexdigest()[:8], 16) / 2**32


def hash_embedding(h: Optional[str], dim: int = 8) -> np.ndarray:
    """Dense signed feature-hashing embedding in [-1, 1]^dim (zeros if missing)."""
    if not h:
        return np.zeros(dim, dtype=np.float32)
    raw = hashlib.sha256(h.encode()).digest()
    while len(raw) < dim * 2:
        raw += hashlib.sha256(raw).digest()
    v = np.frombuffer(raw[: dim * 2], dtype=">u2").astype(np.float32)
    return (v / 32767.5) - 1.0


def _cn_or_dn(cn: str, dn: str) -> str:
    return cn or dn


# --------------------------------------------------------------------------- #
# Extractor
# --------------------------------------------------------------------------- #
class FeatureExtractor:
    def __init__(self, normalize: bool = True, ja3_mode: str = "scalar", ja3_dim: int = 8):
        if ja3_mode not in ("scalar", "embedding"):
            raise ValueError("ja3_mode must be 'scalar' or 'embedding'")
        self.normalize = normalize
        self.ja3_mode = ja3_mode
        self.ja3_dim = ja3_dim

    @property
    def feature_names(self) -> List[str]:
        if self.ja3_mode == "scalar":
            return list(BASE_FEATURES)
        out: List[str] = []
        for n in BASE_FEATURES:
            if n in ("ja3_num", "ja3s_num"):
                p = n.split("_")[0]
                out += [f"{p}_e{i}" for i in range(self.ja3_dim)]
            else:
                out.append(n)
        return out

    def raw_features(self, a: FlowAnalysis) -> Dict[str, float]:
        """Human-readable, un-normalized features (also used by the heuristic)."""
        t, c, e = a.tls, a.cert, a.email
        sni = t.sni or ""
        names = [sni] + ([c.subject_cn] + c.san_dns if c else [])
        f: Dict[str, float] = {
            "duration_s": float(a.duration or 0.0),
            "orig_bytes": float(a.orig_bytes or 0),
            "resp_bytes": float(a.resp_bytes or 0),
            "sni_length": float(len(sni)) if t.observed else MISSING,
            "sni_entropy": shannon_entropy(sni) if sni else MISSING,
            "ja3_num": hash_to_unit(t.ja3),
            "ja3s_num": hash_to_unit(t.ja3s),
            "cert_lifespan_days": MISSING,
            "cert_self_signed": MISSING,
            "cert_pubkey_bits": MISSING,
            "cert_subject_entropy": MISSING,
            "cert_issuer_entropy": MISSING,
            "punycode_present": float(any("xn--" in (n or "").lower() for n in names)),
            "email_has_attachment": float(bool(e.attachments)),
            "email_subject_entropy": max((shannon_entropy(s) for s in e.subjects),
                                         default=MISSING),
            "tls_version": _TLS_NUM.get(t.version, MISSING if t.observed else 0.0),
            "tls_observed": float(t.observed),
            "cert_observed": float(c is not None),
            "cleartext_auth": float(e.cleartext_auth),
            "starttls": float(t.starttls),
        }
        if c is not None:
            if c.lifespan_days is not None:
                f["cert_lifespan_days"] = float(c.lifespan_days)
            f["cert_self_signed"] = float(c.self_signed)
            if c.key_bits:
                f["cert_pubkey_bits"] = float(c.key_bits)
            f["cert_subject_entropy"] = shannon_entropy(_cn_or_dn(c.subject_cn, c.subject))
            f["cert_issuer_entropy"] = shannon_entropy(_cn_or_dn(c.issuer_cn, c.issuer))
        return f

    def transform(self, a: FlowAnalysis) -> np.ndarray:
        raw = self.raw_features(a)
        parts: List[np.ndarray] = []
        for name in BASE_FEATURES:
            v = raw[name]
            if name in ("ja3_num", "ja3s_num") and self.ja3_mode == "embedding":
                parts.append(hash_embedding(a.tls.ja3 if name == "ja3_num" else a.tls.ja3s,
                                            self.ja3_dim))
                continue
            if self.normalize and name in LOG_SCALED and v >= 0:
                v = math.log1p(v)
            parts.append(np.array([v], dtype=np.float32))
        vec = np.concatenate(parts).astype(np.float32)
        assert vec.ndim == 1 and vec.shape[0] == len(self.feature_names)
        return vec

    def transform_batch(self, analyses: Sequence[FlowAnalysis]) -> np.ndarray:
        if not analyses:
            return np.zeros((0, len(self.feature_names)), dtype=np.float32)
        return np.vstack([self.transform(a) for a in analyses])

    def config(self) -> dict:
        return {"normalize": self.normalize, "ja3_mode": self.ja3_mode,
                "ja3_dim": self.ja3_dim, "feature_names": self.feature_names}
