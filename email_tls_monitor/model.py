"""
model.py - ThreatScorer: ML inference (.joblib / .onnx) with a rule-based
fallback. Heuristic indicators are always computed so every rating carries
human-readable evidence, even when an opaque model makes the call.

Heuristic combination is a noisy-OR:  P = 1 - prod(1 - w_i)
so independent weak signals accumulate but never exceed 1.0.
"""
from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

import numpy as np

from dissector import FlowAnalysis, hostname_matches
from features import MISSING, FeatureExtractor

log = logging.getLogger(__name__)

BENIGN, SUSPICIOUS, MALICIOUS = "BENIGN", "SUSPICIOUS", "MALICIOUS"

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
                    ".lnk", ".iso", ".img", ".vhd", ".bat", ".cmd", ".ps1", ".msi",
                    ".docm", ".xlsm", ".pptm", ".jar", ".cab", ".one", ".html", ".htm",
                    ".svg"}
WEAK_CIPHER_TOKENS = ("NULL", "EXPORT", "RC4", "_DES_", "3DES", "DES40", "_anon_",
                      "_MD5")

# Public CAs may not issue leaf certs > 398 days (CA/B Forum, 2020); the cap
# falls further to 200 days from 15 Mar 2026. Longer = private/self-made PKI.
MAX_PUBLIC_LIFESPAN_DAYS = 398
EPHEMERAL_LIFESPAN_DAYS = 7       # note: short-lived (~6 day) public certs exist


@dataclass
class Indicator:
    signal: str
    weight: float
    detail: str = ""

    def to_dict(self) -> dict:
        return {"signal": self.signal, "weight": round(self.weight, 3), "detail": self.detail}


@dataclass
class ThreatRating:
    probability: float
    classification: str
    indicators: List[Indicator] = field(default_factory=list)
    scorer: str = "heuristic"
    heuristic_probability: Optional[float] = None

    def to_dict(self, top_k: int = 5) -> dict:
        return {
            "probability": round(float(self.probability), 4),
            "classification": self.classification,
            "indicators": [i.to_dict() for i in self.indicators[:top_k]],
            "scorer": self.scorer,
            "heuristic_probability": None if self.heuristic_probability is None
            else round(self.heuristic_probability, 4),
        }


class ThreatScorer:
    def __init__(self, model_path: Optional[str] = None,
                 extractor: Optional[FeatureExtractor] = None,
                 thresholds: Tuple[float, float] = (0.35, 0.75),
                 ja3_blocklist: Optional[Set[str]] = None,
                 top_k: int = 5):
        self.extractor = extractor or FeatureExtractor()
        self.suspicious_at, self.malicious_at = thresholds
        if not 0.0 < self.suspicious_at < self.malicious_at <= 1.0:
            raise ValueError("thresholds must satisfy 0 < suspicious < malicious <= 1")
        self.ja3_blocklist = {h.lower() for h in (ja3_blocklist or set())}
        self.top_k = top_k
        self._model = None
        self._onnx = None
        self._pos_index: Optional[int] = None
        self._benign_index: Optional[int] = None
        self.scorer_name = "heuristic"
        if model_path:
            self.load(model_path)

    # ------------------------------------------------------------------ #
    # Model loading
    # ------------------------------------------------------------------ #
    def load(self, path: str) -> None:
        ext = os.path.splitext(path)[1].lower()
        if ext in (".joblib", ".pkl"):
            self._load_joblib(path)
        elif ext == ".onnx":
            self._load_onnx(path)
        else:
            raise ValueError(f"Unsupported model format: {ext} (use .joblib or .onnx)")
        self.scorer_name = f"model:{os.path.basename(path)}"
        log.info("Loaded model %s", path)

    def _load_joblib(self, path: str) -> None:
        import joblib
        obj = joblib.load(path)
        expected = self.extractor.feature_names
        if isinstance(obj, dict):          # bundle: {"model", "feature_names", "thresholds"}
            model = obj["model"]
            names = obj.get("feature_names")
            if names and list(names) != expected:
                raise ValueError("Model feature_names do not match extractor layout; "
                                 "check --ja3-mode / feature version")
            if obj.get("thresholds"):
                self.suspicious_at, self.malicious_at = obj["thresholds"]
        else:
            model = obj
        n_in = getattr(model, "n_features_in_", None)
        if n_in is not None and n_in != len(expected):
            raise ValueError(f"Model expects {n_in} features, extractor produces {len(expected)}")
        if not hasattr(model, "predict_proba") and not hasattr(model, "decision_function"):
            raise TypeError("Model must implement predict_proba or decision_function")
        classes = list(getattr(model, "classes_", []))
        self._pos_index, self._benign_index = self._class_indices(classes)
        self._model = model

    def _load_onnx(self, path: str) -> None:
        import onnxruntime as ort  # optional dependency
        self._onnx = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        shape = self._onnx.get_inputs()[0].shape
        if len(shape) == 2 and isinstance(shape[1], int) and shape[1] != len(self.extractor.feature_names):
            raise ValueError(f"ONNX model expects {shape[1]} features, "
                             f"extractor produces {len(self.extractor.feature_names)}")

    @staticmethod
    def _class_indices(classes: list) -> Tuple[Optional[int], Optional[int]]:
        if not classes:
            return None, None
        norm = [str(c).lower() for c in classes]
        benign = next((i for i, c in enumerate(norm) if c in ("0", "benign", "false")), None)
        if len(classes) == 2:
            pos = 1 - benign if benign is not None else 1
            return pos, benign
        return None, benign   # multi-class: P(threat) = 1 - P(benign)

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #
    def _model_proba(self, X: np.ndarray) -> np.ndarray:
        if self._model is not None:
            m = self._model
            if hasattr(m, "predict_proba"):
                P = np.asarray(m.predict_proba(X))
                if self._pos_index is not None:
                    return P[:, self._pos_index]
                if self._benign_index is not None:
                    return 1.0 - P[:, self._benign_index]
                return P[:, -1]
            d = np.asarray(m.decision_function(X), dtype=np.float64)
            return 1.0 / (1.0 + np.exp(-d))
        # ONNX (skl2onnx convention: outputs = [label, probabilities])
        name = self._onnx.get_inputs()[0].name
        outs = self._onnx.run(None, {name: X.astype(np.float32)})
        for o in outs[1:] + outs[:1]:
            if isinstance(o, list) and o and isinstance(o[0], dict):   # ZipMap
                keys = list(o[0].keys())
                pos = next((k for k in keys if str(k).lower() in ("1", "malicious", "true")), keys[-1])
                return np.array([row[pos] for row in o], dtype=np.float64)
            arr = np.asarray(o)
            if arr.ndim == 2 and arr.dtype.kind == "f":
                return arr[:, -1].astype(np.float64)
        return np.asarray(outs[0], dtype=np.float64).reshape(-1)  # label-only model

    def classify(self, p: float) -> str:
        if p >= self.malicious_at:
            return MALICIOUS
        if p >= self.suspicious_at:
            return SUSPICIOUS
        return BENIGN

    def score(self, vector: np.ndarray, analysis: FlowAnalysis) -> ThreatRating:
        return self.score_batch(vector.reshape(1, -1), [analysis])[0]

    def score_batch(self, X: np.ndarray, analyses: Sequence[FlowAnalysis]) -> List[ThreatRating]:
        heur = [self.heuristic(a) for a in analyses]
        if self._model is None and self._onnx is None:
            return [ThreatRating(p, self.classify(p), ind, "heuristic", p) for p, ind in heur]
        probs = np.clip(self._model_proba(np.asarray(X, dtype=np.float32)), 0.0, 1.0)
        return [ThreatRating(float(p), self.classify(float(p)), ind, self.scorer_name, hp)
                for p, (hp, ind) in zip(probs, heur)]

    # ------------------------------------------------------------------ #
    # Rule-based fallback
    # ------------------------------------------------------------------ #
    def heuristic(self, a: FlowAnalysis) -> Tuple[float, List[Indicator]]:
        f = self.extractor.raw_features(a)
        t, c, e = a.tls, a.cert, a.email
        ind: List[Indicator] = []
        add = lambda s, w, d="": ind.append(Indicator(s, w, d))
        port = a.flow.get("resp_p")
        start = a.flow.get("start") or 0.0

        # --- certificate ------------------------------------------------
        if c is not None:
            if c.self_signed:
                add("self_signed_cert", 0.45, f"Subject == Issuer ({c.subject_cn or c.subject})")
            life = c.lifespan_days
            if life is not None and life <= EPHEMERAL_LIFESPAN_DAYS:
                add("ephemeral_cert_lifespan", 0.20, f"{life:.1f} days")
            elif life is not None and life > MAX_PUBLIC_LIFESPAN_DAYS:
                add("excessive_cert_lifespan", 0.25,
                    f"{life:.0f} days > {MAX_PUBLIC_LIFESPAN_DAYS} (not publicly issuable)")
            if c.not_after and start > c.not_after:
                add("expired_cert", 0.30, "expired at time of capture")
            elif c.not_before and start < c.not_before:
                add("cert_not_yet_valid", 0.30, "notBefore is after capture time")
            alg = (c.key_alg or "").lower()
            if c.key_bits and (("rsa" in alg and c.key_bits < 2048) or
                               ("ec" in alg and c.key_bits < 224)):
                add("weak_cert_key", 0.30, f"{c.key_alg} {c.key_bits} bit")
            if "md5" in (c.sig_alg or "").lower() or "sha1with" in (c.sig_alg or "").lower():
                add("weak_cert_signature", 0.20, c.sig_alg)
            ent = f["cert_subject_entropy"]
            if c.subject_cn and len(c.subject_cn) >= 16 and ent > 4.0:
                add("high_entropy_cert_subject", 0.15, f"{ent:.2f} bits/char")
        if t.validation_status and t.validation_status.lower() != "ok" \
                and not (c is not None and c.self_signed and "self" in t.validation_status.lower()):
            add("cert_validation_failed", 0.25, t.validation_status)
        if t.sni and c is not None and t.sni_matches_cert is False \
                and not hostname_matches(t.sni, c):
            add("sni_cert_mismatch", 0.20, f"SNI {t.sni} not in cert names")

        # --- names ------------------------------------------------------
        if f["punycode_present"] > 0:
            add("punycode_domain", 0.35, "xn-- label in SNI/certificate")
        if f["sni_entropy"] != MISSING and f["sni_length"] >= 16 and f["sni_entropy"] > 4.0:
            add("high_entropy_sni", 0.20, f"{t.sni} ({f['sni_entropy']:.2f} bits/char)")

        # --- TLS parameters ---------------------------------------------
        if t.version in ("SSLv2", "SSLv3"):
            add("obsolete_ssl", 0.40, t.version)
        elif t.version in ("TLSv10", "TLSv11"):
            add("deprecated_tls", 0.25, f"{t.version} (RFC 8996)")
        if t.cipher and any(tok in t.cipher for tok in WEAK_CIPHER_TOKENS):
            add("weak_cipher", 0.30, t.cipher)
        if t.ja3 and t.ja3.lower() in self.ja3_blocklist:
            add("ja3_blocklisted", 0.80, t.ja3)
        if t.ja3s and t.ja3s.lower() in self.ja3_blocklist:
            add("ja3s_blocklisted", 0.60, t.ja3s)

        # --- email content / posture -------------------------------------
        if e.cleartext_auth:
            add("cleartext_auth", 0.30, "credentials sent before/without TLS")
        if not t.observed and port in (587, 110, 143):
            add("no_tls_on_client_port", 0.15, f"port {port} session never upgraded")
        elif not t.observed and port == 25:
            add("plaintext_smtp_relay", 0.05, "opportunistic TLS not used")
        for att in e.attachments:
            name = (att.get("filename") or "").lower()
            ext = os.path.splitext(name)[1]
            double_ext_archive = name.count(".") >= 2 and ext in (".zip", ".rar", ".7z")
            if ext in RISKY_EXTENSIONS or double_ext_archive:
                add("risky_attachment", 0.35, att.get("filename", ""))
                break
        se = f["email_subject_entropy"]
        longest = max((len(s) for s in e.subjects), default=0)
        if se != MISSING and longest >= 20 and se > 4.8:
            add("high_entropy_subject", 0.20, f"{se:.2f} bits/char")

        p = 1.0 - math.prod(1.0 - i.weight for i in ind) if ind else 0.02
        ind.sort(key=lambda i: i.weight, reverse=True)
        return float(min(max(p, 0.0), 1.0)), ind
