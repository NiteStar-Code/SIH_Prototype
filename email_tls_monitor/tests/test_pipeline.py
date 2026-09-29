"""Offline regression tests (no Zeek needed). Run: python -m pytest -q tests/"""
import json
import os
import subprocess
import sys

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scapy.all import IP, TCP, Ether, Raw  # noqa: E402

from capture import FlowTracker, flows_from_pcap  # noqa: E402
from dissector import Dissector, ZeekRunner, parse_client_hello, read_zeek_log  # noqa: E402
from features import BASE_FEATURES, FeatureExtractor, hash_to_unit, shannon_entropy  # noqa: E402
from model import ThreatScorer  # noqa: E402


@pytest.fixture(scope="session")
def sample(tmp_path_factory):
    d = tmp_path_factory.mktemp("sample")
    pcap, certs = str(d / "s.pcap"), str(d / "certs")
    subprocess.run([sys.executable, os.path.join(ROOT, "samples", "generate_sample_pcap.py"),
                    pcap, certs], check=True, capture_output=True)
    return pcap, certs


def analyses_for(pcap, **kw):
    flows = list(flows_from_pcap(pcap, FlowTracker(timeout=4)))
    return flows, Dissector(engine="native", **kw).analyze(flows)


# ---------------------------------------------------------------- features
def test_entropy_and_hash():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-9
    assert 0.0 <= hash_to_unit("ffffffff" + "0" * 24) < 1.0
    assert hash_to_unit("") == -1.0


def test_ja3_known_vector():
    # JA3 string -> md5 must equal the reference formula, GREASE stripped
    import struct
    sni = b"example.com"
    exts = (struct.pack("!HH", 0x0A0A, 0) +
            struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni +
            struct.pack("!HHH", 10, 6, 4) + struct.pack("!HH", 0x1A1A, 29) +
            struct.pack("!HHB", 11, 2, 1) + b"\x00")
    body = (struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" +
            struct.pack("!HHH", 4, 0x2A2A, 0xC02F) + b"\x01\x00" +
            struct.pack("!H", len(exts)) + exts)
    ch = parse_client_hello(body)
    assert ch["sni"] == "example.com"
    assert ch["ja3_string"] == "771,49199,0-10-11,29,0"


# ---------------------------------------------------------------- capture
def _p(src, sport, dst, dport, flags, t, payload=b""):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / \
        TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        p = p / Raw(payload)
    p.time = t
    return p


def test_tracker_timeout_fin_rst_and_stragglers():
    tr = FlowTracker(timeout=3)
    assert tr.process(_p("1.1.1.1", 4000, "2.2.2.2", 25, "S", 0)) == []
    assert tr.process(_p("2.2.2.2", 25, "1.1.1.1", 4000, "SA", 0.1)) == []
    assert tr.expire(2.0) == []
    done = tr.expire(3.2)
    assert len(done) == 1 and done[0].close_reason == "timeout"
    assert done[0].orig == ("1.1.1.1", 4000) and done[0].protocol == "SMTP"

    tr.process(_p("1.1.1.1", 4001, "2.2.2.2", 993, "S", 10))
    assert tr.process(_p("1.1.1.1", 4001, "2.2.2.2", 993, "FA", 11)) == []
    done = tr.process(_p("2.2.2.2", 993, "1.1.1.1", 4001, "FA", 11.1))
    assert done[0].close_reason == "fin" and done[0].implicit_tls
    assert tr.process(_p("1.1.1.1", 4001, "2.2.2.2", 993, "A", 11.2)) == []  # straggler
    assert len(tr) == 0

    tr.process(_p("1.1.1.1", 4002, "2.2.2.2", 110, "PA", 20, b"USER x\r\n"))
    assert tr.process(_p("2.2.2.2", 110, "1.1.1.1", 4002, "R", 20.5))[0].close_reason == "rst"
    assert tr.process(_p("8.8.8.8", 1234, "9.9.9.9", 80, "S", 21)) == []    # not email


# ---------------------------------------------------------------- end to end
def test_native_end_to_end(sample):
    pcap, certs = sample
    flows, res = analyses_for(pcap, ca_file=os.path.join(certs, "test-ca.pem"))
    by_port = {r.flow["resp_p"]: r for r in res}
    assert set(by_port) == {587, 465, 993, 25, 110}

    smtp = by_port[587]
    assert smtp.email.cleartext_auth and "DATA" in smtp.email.commands
    assert smtp.email.attachments[0]["filename"] == "invoice.pdf.exe"
    assert smtp.email.subjects[0].startswith("Urgent invoice")

    s465 = by_port[465]
    assert s465.tls.version == "TLSv12" and "3DES" in s465.tls.cipher
    assert s465.cert.self_signed and s465.cert.key_bits == 1024 and s465.cert.punycode
    assert 3649 <= s465.cert.lifespan_days <= 3651
    assert s465.tls.handshake_duration is not None

    assert by_port[993].tls.version == "TLSv13" and by_port[993].cert is None
    assert by_port[25].tls.starttls and by_port[25].tls.validation_status == "ok"
    assert by_port[25].tls.sni_matches_cert is True


def test_vector_shape_and_modes(sample):
    _, res = analyses_for(sample[0])
    fx = FeatureExtractor()
    X = fx.transform_batch(res)
    assert X.dtype == np.float32 and X.shape == (5, len(BASE_FEATURES))
    fe = FeatureExtractor(ja3_mode="embedding", ja3_dim=4)
    v = fe.transform(res[0])
    assert v.shape == (len(BASE_FEATURES) - 2 + 8,) and len(fe.feature_names) == v.shape[0]


def test_heuristic_ranks(sample):
    pcap, certs = sample
    _, res = analyses_for(pcap, ca_file=os.path.join(certs, "test-ca.pem"))
    sc = ThreatScorer()
    rat = {r.flow["resp_p"]: sc.score(sc.extractor.transform(r), r) for r in res}
    assert rat[465].classification == "MALICIOUS"
    assert rat[587].classification == "SUSPICIOUS"
    assert rat[25].classification == "BENIGN" and rat[993].classification == "BENIGN"
    assert rat[465].indicators[0].signal == "self_signed_cert"


def test_joblib_model_bundle(sample, tmp_path):
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    _, res = analyses_for(sample[0])
    fx = FeatureExtractor()
    X = fx.transform_batch(res)
    y = np.array([1 if r.flow["resp_p"] in (465, 587) else 0 for r in res])
    clf = RandomForestClassifier(n_estimators=20, random_state=0).fit(X, y)
    path = str(tmp_path / "m.joblib")
    joblib.dump({"model": clf, "feature_names": fx.feature_names}, path)
    sc = ThreatScorer(path, extractor=fx)
    rs = sc.score_batch(X, res)
    assert all(0.0 <= r.probability <= 1.0 for r in rs)
    assert rs[0].scorer.startswith("model:") and rs[0].heuristic_probability is not None
    with pytest.raises(ValueError):   # layout mismatch is refused
        ThreatScorer(path, extractor=FeatureExtractor(ja3_mode="embedding"))


# ---------------------------------------------------------------- zeek merge
def test_zeek_merge_with_fake_logs(sample, monkeypatch, tmp_path):
    pcap, _ = sample
    flows = list(flows_from_pcap(pcap, FlowTracker(timeout=4)))
    f465 = next(f for f in flows if f.resp[1] == 465)
    f587 = next(f for f in flows if f.resp[1] == 587)
    extract = tmp_path / "extract"
    extract.mkdir()
    # reuse the DER the native engine saw as the "extracted" certificate
    from dissector import _handshake_msgs, _reassemble, _TLS_HS_START, parse_certificate_msg
    _, srv = _reassemble(f465)
    der = next(parse_certificate_msg(b) for t, b in
               _handshake_msgs(srv.data, _TLS_HS_START.search(srv.data).start()) if t == 11)[0]
    (extract / "extract-1.0-SSL-FcertA1").write_bytes(der)
    import hashlib
    fp = hashlib.sha256(der).hexdigest()

    def conn(f, uid):
        return {"ts": f.start, "uid": uid, "id.orig_h": f.orig[0], "id.orig_p": f.orig[1],
                "id.resp_h": f.resp[0], "id.resp_p": f.resp[1], "duration": 1.5,
                "orig_bytes": 999, "resp_bytes": 111, "conn_state": "SF"}
    logs = {
        "conn": [conn(f465, "C465"), conn(f587, "C587")],
        "ssl": [{"uid": "C465", "version": "TLSv12", "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                 "server_name": "xn--pple-43d.com", "validation_status": "self signed certificate",
                 "established": True, "ja3": "a" * 32, "ja3s": "b" * 32,
                 "handshake_duration": 0.2, "cert_chain_fps": [fp]}],
        "smtp": [{"uid": "C587", "subject": "Zeek subject", "mailfrom": "a@lab", "rcptto": ["b@lab"]}],
        "files": [{"uid": "C587", "source": "SMTP", "filename": "x.js", "mime_type": "text/plain",
                   "seen_bytes": 10}],
        "x509": [], "email_cmds": [{"uid": "C587", "commands": ["ehlo", "auth", "data"]}],
        "_extract_dir": str(extract),
    }
    d = Dissector(engine="native")
    d.use_zeek = True
    monkeypatch.setattr(ZeekRunner, "run", lambda self, p, wd: logs)
    res = {r.flow["resp_p"]: r for r in d.analyze([f465, f587])}
    r = res[465]
    assert r.engine == "zeek+native" and r.zeek_uid == "C465" and r.orig_bytes == 999
    assert r.tls.ja3 == "a" * 32 and r.tls.handshake_duration == 0.2
    assert r.cert and r.cert.self_signed and r.cert.source == "openssl"
    assert res[587].email.attachments[0]["filename"] == "x.js"
    assert res[587].email.cleartext_auth and "Zeek subject" in res[587].email.subjects


def test_read_zeek_tsv(tmp_path):
    p = tmp_path / "ssl.log"
    p.write_text("#separator \\x09\n#set_separator\t,\n#fields\tuid\tversion\tcert_chain_fps\n"
                 "#types\tstring\tstring\tvector[string]\nCx\tTLSv12\taa,bb\n#close\n")
    rows = read_zeek_log(str(p))
    assert rows == [{"uid": "Cx", "version": "TLSv12", "cert_chain_fps": ["aa", "bb"]}]


def test_cli_smoke(sample, tmp_path):
    out = tmp_path / "o.jsonl"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "app.py"), "--pcap", sample[0],
                        "--engine", "native", "--output", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    recs = [json.loads(l) for l in out.read_text().splitlines()]
    assert len(recs) == 5 and all(len(x["vector"]) == 20 for x in recs)
