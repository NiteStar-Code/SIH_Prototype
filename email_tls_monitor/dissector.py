"""
dissector.py - Protocol dissection for email flows.

Module A  SMTP/IMAP/POP3 metadata      (Zeek conn/smtp/files + custom email_cmds.log)
Module B  TLS handshake analysis       (Zeek ssl.log, + handshake_duration script)
Module C  X.509 certificate parsing    (Zeek extract-all-files -> `openssl x509`)
Module D  JA3 / JA3S                   (Zeek `ja3` package)

A built-in *native* dissector (pure Python TCP reassembly + TLS record parsing)
always runs as well. It fills any field Zeek did not produce (e.g. JA3 when the
package is missing, certificates when extraction failed) and is the only engine
when Zeek is not installed (`--engine native`, or Windows without WSL).

Important protocol limits (hold for both engines):
  * TLS 1.3 encrypts the Certificate message -> no passive cert features.
  * After STARTTLS / on implicit-TLS ports, commands and subjects are encrypted.
"""
from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from capture import Flow, write_flows_pcap

log = logging.getLogger(__name__)

try:  # IANA cipher-suite names (only used by the native engine)
    from scapy.layers.tls.crypto.suites import _tls_cipher_suites as _CIPHER_NAMES  # type: ignore
except Exception:  # pragma: no cover
    _CIPHER_NAMES = {}

TLS_VERSION_NAMES = {0x0002: "SSLv2", 0x0300: "SSLv3", 0x0301: "TLSv10",
                     0x0302: "TLSv11", 0x0303: "TLSv12", 0x0304: "TLSv13"}


# =========================================================================== #
# Result data model
# =========================================================================== #
@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    subject_cn: str = ""
    issuer_cn: str = ""
    not_before: Optional[float] = None   # epoch seconds
    not_after: Optional[float] = None
    lifespan_days: Optional[float] = None
    self_signed: bool = False            # Subject == Issuer
    key_alg: str = ""
    key_bits: Optional[int] = None
    sig_alg: str = ""
    san_dns: List[str] = field(default_factory=list)
    punycode: bool = False               # 'xn--' in CN or any SAN
    sha256: str = ""
    source: str = ""                     # openssl | zeek-x509.log


@dataclass
class TLSInfo:
    observed: bool = False
    starttls: bool = False
    version: str = ""                    # Zeek naming: TLSv12, TLSv13, ...
    cipher: str = ""
    sni: str = ""
    validation_status: str = ""          # "ok" or OpenSSL/Zeek error string
    sni_matches_cert: Optional[bool] = None
    handshake_duration: Optional[float] = None  # seconds
    established: Optional[bool] = None
    ja3: str = ""
    ja3s: str = ""
    ja3_string: str = ""
    ja3s_string: str = ""
    chain_length: int = 0


@dataclass
class EmailInfo:
    commands: List[str] = field(default_factory=list)   # cleartext verbs only
    subjects: List[str] = field(default_factory=list)
    mail_from: List[str] = field(default_factory=list)
    rcpt_to: List[str] = field(default_factory=list)
    attachments: List[dict] = field(default_factory=list)  # filename, mime_type, size
    cleartext_auth: bool = False


@dataclass
class FlowAnalysis:
    flow: dict                            # capture.Flow.summary()
    engine: str = "native"
    zeek_uid: str = ""
    conn_state: str = ""
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    tls: TLSInfo = field(default_factory=TLSInfo)
    cert: Optional[CertInfo] = None
    email: EmailInfo = field(default_factory=EmailInfo)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# =========================================================================== #
# Module C - OpenSSL certificate parsing
# =========================================================================== #
_DN_CN = re.compile(r"(?:^|,)\s*CN=((?:\\.|[^,])*)")


def _cn(dn: str) -> str:
    m = _DN_CN.search(dn or "")
    return m.group(1).replace("\\,", ",").strip() if m else ""


def _parse_openssl_date(s: str) -> Optional[float]:
    s = " ".join(s.split())  # "Jan  1 00:00:00 2025 GMT" -> single spaces
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def der_to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def hostname_matches(host: str, cert: CertInfo) -> bool:
    """RFC 6125-style match of SNI against SAN dNSNames (CN only if no SANs)."""
    host = (host or "").lower().rstrip(".")
    names = [n.lower() for n in cert.san_dns] or ([cert.subject_cn.lower()] if cert.subject_cn else [])
    for n in names:
        if n == host:
            return True
        if n.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == n[2:]:
                return True
    return False


class OpenSSLParser:
    def __init__(self, openssl_bin: str = "openssl", ca_file: Optional[str] = None,
                 timeout: float = 15.0):
        self.bin = openssl_bin
        self.ca_file = ca_file
        self.timeout = timeout
        self.available = shutil.which(openssl_bin) is not None
        if not self.available:
            log.warning("openssl binary '%s' not found - certificate parsing disabled", openssl_bin)

    def _x509_text(self, path: str) -> Optional[str]:
        for inform in ("DER", "PEM"):
            try:
                r = subprocess.run(
                    [self.bin, "x509", "-in", path, "-inform", inform,
                     "-text", "-noout", "-nameopt", "RFC2253"],
                    capture_output=True, text=True, timeout=self.timeout)
            except (OSError, subprocess.TimeoutExpired) as e:
                log.debug("openssl failed on %s: %s", path, e)
                return None
            if r.returncode == 0:
                return r.stdout
        return None

    def parse_file(self, path: str) -> Optional[CertInfo]:
        if not self.available:
            return None
        text = self._x509_text(path)
        if text is None:
            return None
        info = self.parse_text(text)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            if raw.startswith(b"-----BEGIN"):
                raw = base64.b64decode(b"".join(
                    l for l in raw.splitlines() if l and not l.startswith(b"-----")))
            info.sha256 = hashlib.sha256(raw).hexdigest()
        except OSError:
            pass
        return info

    def parse_der(self, der: bytes) -> Optional[CertInfo]:
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tf:
            tf.write(der)
            p = tf.name
        try:
            return self.parse_file(p)
        finally:
            os.unlink(p)

    @staticmethod
    def parse_text(text: str) -> CertInfo:
        """Parse `openssl x509 -text -noout -nameopt RFC2253` output."""
        c = CertInfo(source="openssl")

        def grab(pattern: str) -> str:
            m = re.search(pattern, text, re.M)
            return m.group(1).strip() if m else ""

        c.subject = grab(r"^\s*Subject:\s*(.*)$")
        c.issuer = grab(r"^\s*Issuer:\s*(.*)$")
        c.subject_cn, c.issuer_cn = _cn(c.subject), _cn(c.issuer)
        c.not_before = _parse_openssl_date(grab(r"Not Before\s*:\s*(.*)$"))
        c.not_after = _parse_openssl_date(grab(r"Not After\s*:\s*(.*)$"))
        if c.not_before is not None and c.not_after is not None:
            c.lifespan_days = round((c.not_after - c.not_before) / 86400.0, 3)
        c.self_signed = bool(c.subject) and c.subject == c.issuer
        c.key_alg = grab(r"Public Key Algorithm:\s*(\S+)")
        c.sig_alg = grab(r"Signature Algorithm:\s*(\S+)")
        bits = grab(r"Public-Key:\s*\((\d+) bit\)")      # OpenSSL 1.1 and 3.x
        if bits:
            c.key_bits = int(bits)
        elif c.key_alg.upper() in ("ED25519", "X25519"):
            c.key_bits = 256
        elif c.key_alg.upper() in ("ED448", "X448"):
            c.key_bits = 456
        m = re.search(r"X509v3 Subject Alternative Name:.*?\n\s*(.+)$", text, re.M)
        if m:
            c.san_dns = [x.strip()[4:] for x in m.group(1).split(",")
                         if x.strip().startswith("DNS:")]
        names = [c.subject_cn] + c.san_dns
        c.punycode = any("xn--" in n.lower() for n in names if n)
        return c

    def verify_chain(self, chain_der: List[bytes], at_time: Optional[float] = None) -> str:
        """`openssl verify` the leaf with the rest of the chain as untrusted.
        Returns 'ok' or the OpenSSL error string (Zeek-like semantics)."""
        if not self.available or not chain_der:
            return ""
        with tempfile.TemporaryDirectory() as d:
            leaf = os.path.join(d, "leaf.pem")
            with open(leaf, "w") as fh:
                fh.write(der_to_pem(chain_der[0]))
            cmd = [self.bin, "verify"]
            if self.ca_file:
                cmd += ["-CAfile", self.ca_file]
            if len(chain_der) > 1:
                inter = os.path.join(d, "untrusted.pem")
                with open(inter, "w") as fh:
                    fh.write("".join(der_to_pem(x) for x in chain_der[1:]))
                cmd += ["-untrusted", inter]
            if at_time:
                cmd += ["-attime", str(int(at_time))]   # validate as of capture time
            cmd.append(leaf)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            except (OSError, subprocess.TimeoutExpired):
                return ""
            out = r.stdout + r.stderr
            if r.returncode == 0 and ": OK" in out:
                return "ok"
            m = re.search(r"error \d+ at \d+ depth lookup:\s*(.+)", out)
            return m.group(1).strip() if m else "verify failed"


# =========================================================================== #
# Native engine - TCP reassembly + TLS / email parsing
# =========================================================================== #
class _Stream:
    """One direction of a reassembled TCP stream with offset->timestamp map."""

    def __init__(self):
        self.data = b""
        self._marks: List[Tuple[int, float]] = []   # (stream offset, ts)
        self.gaps = 0

    def time_at(self, off: int) -> Optional[float]:
        t = None
        for o, ts in self._marks:
            if o > off:
                break
            t = ts
        return t


def _reassemble(flow: Flow) -> Tuple[_Stream, _Stream]:
    from scapy.all import TCP  # local import keeps module import light

    segs = {True: [], False: []}   # from_orig -> [(seq, ts, payload)]
    isn = {}
    for p in flow.packets:
        t = p[TCP]
        from_orig = (int(t.sport) == flow.orig[1] and
                     str(t.underlayer.src) == flow.orig[0])
        if int(t.flags) & 0x02:
            isn[from_orig] = (int(t.seq) + 1) & 0xFFFFFFFF
        pl = bytes(t.payload)
        if pl:
            segs[from_orig].append((int(t.seq), float(p.time), pl))

    out = {}
    for direction, items in segs.items():
        s = _Stream()
        if items:
            ref = isn.get(direction, items[0][0])
            rel = lambda q: ((q - ref + 2**31) % 2**32) - 2**31  # signed, wrap-safe
            items = sorted(((rel(q), ts, pl) for q, ts, pl in items), key=lambda x: (x[0], -len(x[2])))
            nxt = min(0, items[0][0]) if direction in isn else items[0][0]
            for r, ts, pl in items:
                end = r + len(pl)
                if end <= nxt:
                    continue                       # retransmission
                if r > nxt:
                    s.gaps += 1                    # missing bytes - just splice
                elif r < nxt:
                    pl = pl[nxt - r:]              # overlap - trim
                s._marks.append((len(s.data), ts))
                s.data += pl
                nxt = end
        out[direction] = s
    return out[True], out[False]


def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


_TLS_HS_START = re.compile(rb"\x16\x03[\x00-\x04]..[\x01\x02]", re.S)


def _tls_records(data: bytes, start: int):
    i = start
    while i + 5 <= len(data):
        ctype, major, length = data[i], data[i + 1], _u16(data, i + 3)
        if ctype not in (20, 21, 22, 23, 24) or major != 3 or length > 18432:
            return
        if i + 5 + length > len(data):
            return
        yield i, ctype, data[i + 5:i + 5 + length]
        i += 5 + length


def _handshake_msgs(data: bytes, start: int) -> List[Tuple[int, bytes]]:
    """Concatenate the leading run of handshake records and split messages."""
    buf = b""
    for _, ctype, body in _tls_records(data, start):
        if ctype != 22:
            break
        buf += body
    msgs, i = [], 0
    while i + 4 <= len(buf):
        mtype, mlen = buf[i], int.from_bytes(buf[i + 1:i + 4], "big")
        if i + 4 + mlen > len(buf):
            break
        msgs.append((mtype, buf[i + 4:i + 4 + mlen]))
        i += 4 + mlen
    return msgs


def _parse_extensions(b: bytes, p: int) -> List[Tuple[int, bytes]]:
    exts = []
    if p + 2 > len(b):
        return exts
    end = min(len(b), p + 2 + _u16(b, p))
    p += 2
    while p + 4 <= end:
        et, el = _u16(b, p), _u16(b, p + 2)
        exts.append((et, b[p + 4:p + 4 + el]))
        p += 4 + el
    return exts


def parse_client_hello(b: bytes) -> dict:
    p = 0
    ver = _u16(b, p); p += 2 + 32
    p += 1 + b[p]                                   # session id
    cl = _u16(b, p); p += 2
    ciphers = [_u16(b, p + i) for i in range(0, cl, 2)]; p += cl
    p += 1 + b[p]                                   # compression methods
    exts = _parse_extensions(b, p)
    sni, curves, pfs, sup = "", [], [], []
    for et, ed in exts:
        if et == 0 and len(ed) >= 5:                # server_name
            n = _u16(ed, 3)
            sni = ed[5:5 + n].decode("ascii", "replace")
        elif et == 10 and len(ed) >= 2:             # supported_groups
            curves = [_u16(ed, 2 + i) for i in range(0, _u16(ed, 0), 2)]
        elif et == 11 and ed:                       # ec_point_formats
            pfs = list(ed[1:1 + ed[0]])
        elif et == 43 and ed:                       # supported_versions
            sup = [_u16(ed, 1 + i) for i in range(0, ed[0], 2)]
    ja3_str = ",".join([
        str(ver),
        "-".join(str(c) for c in ciphers if not _is_grease(c)),
        "-".join(str(e) for e, _ in exts if not _is_grease(e)),
        "-".join(str(c) for c in curves if not _is_grease(c)),
        "-".join(str(x) for x in pfs),
    ])
    return {"version": ver, "sni": sni, "supported_versions": sup,
            "ja3_string": ja3_str, "ja3": hashlib.md5(ja3_str.encode()).hexdigest()}


def parse_server_hello(b: bytes) -> dict:
    p = 0
    ver = _u16(b, p); p += 2 + 32
    p += 1 + b[p]
    cipher = _u16(b, p); p += 2
    p += 1                                          # compression
    exts = _parse_extensions(b, p)
    selected = ver
    for et, ed in exts:
        if et == 43 and len(ed) >= 2:
            selected = _u16(ed, 0)
    ja3s_str = f"{ver},{cipher}," + "-".join(str(e) for e, _ in exts)
    return {"version": selected, "cipher": cipher, "ja3s_string": ja3s_str,
            "ja3s": hashlib.md5(ja3s_str.encode()).hexdigest()}


def parse_certificate_msg(b: bytes) -> List[bytes]:
    """TLS <= 1.2 Certificate message -> list of DER certs (leaf first)."""
    certs, total = [], int.from_bytes(b[0:3], "big")
    p, end = 3, min(len(b), 3 + total)
    while p + 3 <= end:
        n = int.from_bytes(b[p:p + 3], "big")
        certs.append(b[p + 3:p + 3 + n])
        p += 3 + n
    return certs


SMTP_VERBS = {"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "HELP",
              "NOOP", "QUIT", "STARTTLS", "AUTH", "BDAT", "ETRN"}
POP3_VERBS = {"USER", "PASS", "APOP", "AUTH", "STAT", "LIST", "RETR", "DELE", "NOOP",
              "RSET", "QUIT", "TOP", "UIDL", "CAPA", "STLS"}
IMAP_VERBS = {"CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "AUTHENTICATE", "LOGIN",
              "SELECT", "EXAMINE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE",
              "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE",
              "EXPUNGE", "SEARCH", "FETCH", "STORE", "COPY", "UID", "IDLE", "ENABLE",
              "ID", "NAMESPACE", "MOVE"}
AUTH_VERBS = {"AUTH", "AUTHENTICATE", "LOGIN", "USER", "PASS", "APOP"}


def _parse_mime(raw: bytes) -> Tuple[str, List[dict]]:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    try:
        subject = str(msg.get("subject", "") or "")
    except Exception:
        subject = ""
    atts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        if fn or part.get_content_disposition() == "attachment":
            try:
                size = len(part.get_payload(decode=True) or b"")
            except Exception:
                size = 0
            atts.append({"filename": fn or "", "mime_type": part.get_content_type(),
                         "size": size})
    return subject, atts


def parse_cleartext_email(protocol: str, client: bytes) -> EmailInfo:
    info = EmailInfo()
    lines = client.split(b"\r\n") if b"\r\n" in client else client.split(b"\n")
    in_data, data_buf = False, []
    for raw in lines:
        if in_data:
            if raw == b".":
                body = b"\r\n".join(l[1:] if l.startswith(b"..") else l for l in data_buf)
                subj, atts = _parse_mime(body)
                if subj:
                    info.subjects.append(subj)
                info.attachments.extend(atts)
                in_data, data_buf = False, []
            else:
                data_buf.append(raw)
            continue
        toks = raw.decode("latin-1", "replace").strip().split()
        if not toks:
            continue
        if protocol == "IMAP":
            verb = toks[1].upper() if len(toks) > 1 else ""
            verbs = IMAP_VERBS
        else:
            verb = toks[0].upper()
            verbs = SMTP_VERBS if protocol == "SMTP" else POP3_VERBS
        if verb not in verbs:
            continue
        info.commands.append(verb)
        if protocol == "SMTP":
            arg = " ".join(toks[1:])
            if verb == "MAIL":
                info.mail_from.append(arg.partition(":")[2].strip("<> "))
            elif verb == "RCPT":
                info.rcpt_to.append(arg.partition(":")[2].strip("<> "))
            elif verb == "DATA":
                in_data = True
    info.cleartext_auth = any(c in AUTH_VERBS for c in info.commands)
    return info


class NativeDissector:
    def __init__(self, openssl: OpenSSLParser):
        self.openssl = openssl

    def analyze(self, flow: Flow) -> FlowAnalysis:
        a = FlowAnalysis(flow=flow.summary(), engine="native",
                         duration=flow.duration, orig_bytes=flow.orig_bytes,
                         resp_bytes=flow.resp_bytes,
                         conn_state=flow.close_reason.upper())
        try:
            cli, srv = _reassemble(flow)
        except Exception as e:  # pragma: no cover - malformed captures
            a.notes.append(f"reassembly failed: {e}")
            return a
        if cli.gaps or srv.gaps:
            a.notes.append(f"stream gaps: client={cli.gaps} server={srv.gaps}")

        m = _TLS_HS_START.search(cli.data)
        c_start = m.start() if m and cli.data[m.start() + 5] == 1 else -1
        plaintext = cli.data if c_start < 0 else cli.data[:c_start]
        if plaintext and not flow.implicit_tls:
            a.email = parse_cleartext_email(flow.protocol, plaintext)

        if c_start >= 0:
            self._tls(flow, a, cli, srv, c_start)
        if a.tls.observed and not flow.implicit_tls:
            a.tls.starttls = True
        return a

    def _tls(self, flow: Flow, a: FlowAnalysis, cli: _Stream, srv: _Stream, c_start: int):
        t = a.tls
        t.observed = True
        try:
            for mtype, body in _handshake_msgs(cli.data, c_start):
                if mtype == 1:
                    ch = parse_client_hello(body)
                    t.sni, t.ja3, t.ja3_string = ch["sni"], ch["ja3"], ch["ja3_string"]
                    break
        except (IndexError, ValueError) as e:
            a.notes.append(f"ClientHello parse error: {e}")

        # handshake end ~ first client ApplicationData record (TLS1.3 Finished
        # is also sent as type 23; in TLS1.2 it's the first request after Finished)
        t0 = cli.time_at(c_start)
        for off, ctype, _ in _tls_records(cli.data, c_start):
            if ctype == 23:
                t1 = cli.time_at(off)
                if t0 is not None and t1 is not None:
                    t.handshake_duration = round(max(0.0, t1 - t0), 6)
                t.established = True
                break

        ms = _TLS_HS_START.search(srv.data)
        if not ms:
            return
        chain: List[bytes] = []
        try:
            for mtype, body in _handshake_msgs(srv.data, ms.start()):
                if mtype == 2:
                    sh = parse_server_hello(body)
                    t.version = TLS_VERSION_NAMES.get(sh["version"], hex(sh["version"]))
                    t.cipher = _CIPHER_NAMES.get(sh["cipher"], f"0x{sh['cipher']:04x}")
                    t.ja3s, t.ja3s_string = sh["ja3s"], sh["ja3s_string"]
                elif mtype == 11:
                    chain = parse_certificate_msg(body)
        except (IndexError, ValueError) as e:
            a.notes.append(f"ServerHello parse error: {e}")

        if t.version == "TLSv13":
            a.notes.append("TLS 1.3: certificate is encrypted, cert features unavailable")
        if chain:
            t.chain_length = len(chain)
            cert = self.openssl.parse_der(chain[0])
            if cert:
                a.cert = cert
                t.validation_status = self.openssl.verify_chain(chain, at_time=flow.start)
                if t.sni:
                    t.sni_matches_cert = hostname_matches(t.sni, cert)


# =========================================================================== #
# Zeek engine
# =========================================================================== #
ZEEK_SCRIPT = r"""
@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/smtp
@load base/protocols/pop3
@load base/protocols/imap
@load base/files/x509
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/files/extract-all-files

# Bound what extract-all-files writes (attachments are extracted too!)
redef FileExtract::default_limit = 16777216;

module EmailMon;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts:       time           &log;
        uid:      string         &log;
        id:       conn_id        &log;
        proto:    string         &log;
        commands: vector of string &log;
    };
}

redef record SSL::Info += {
    hs_start:           time     &optional;
    handshake_duration: interval &log &optional;
};

redef record connection += {
    email_cmds:  vector of string &optional;
    email_proto: string           &optional;
};

event zeek_init()
    {
    Log::create_stream(EmailMon::LOG, [$columns=Info, $path="email_cmds"]);
    }

function add_cmd(c: connection, proto: string, cmd: string)
    {
    if ( ! c?$email_cmds )
        {
        local v: vector of string = vector();
        c$email_cmds = v;
        c$email_proto = proto;
        }
    if ( |c$email_cmds| < 128 )
        c$email_cmds[|c$email_cmds|] = to_upper(cmd);
    }

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
    { add_cmd(c, "SMTP", command); }

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
    { add_cmd(c, "POP3", command); }

event imap_starttls(c: connection)
    { add_cmd(c, "IMAP", "STARTTLS"); }

# Handshake timing: first ClientHello -> ssl_established
event ssl_handshake_message(c: connection, is_client: bool, msg_type: count, length: count) &priority=-5
    {
    if ( is_client && msg_type == 1 && c?$ssl && ! c$ssl?$hs_start )
        c$ssl$hs_start = network_time();
    }

event ssl_established(c: connection) &priority=5
    {
    if ( c?$ssl && c$ssl?$hs_start )
        c$ssl$handshake_duration = network_time() - c$ssl$hs_start;
    }

event connection_state_remove(c: connection)
    {
    if ( c?$email_cmds )
        Log::write(EmailMon::LOG, [$ts=c$start_time, $uid=c$uid, $id=c$id,
                                   $proto=c$email_proto, $commands=c$email_cmds]);
    }
"""


def read_zeek_log(path: str) -> List[dict]:
    """Read a Zeek log written as JSON lines (or classic TSV as a fallback)."""
    if not os.path.exists(path):
        return []
    rows: List[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.startswith("{"):
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return rows
        fields, sep, set_sep, unset = [], "\t", ",", {"-", "(empty)"}
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
            elif line.startswith("#set_separator"):
                set_sep = line.split(sep, 1)[1]
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#") or not fields:
                continue
            else:
                vals = line.split(sep)
                row = {}
                for k, v in zip(fields, vals):
                    if v in unset:
                        continue
                    row[k] = v.split(set_sep) if k.endswith(("fps", "fuids", "conn_uids",
                                                             "rcptto", "commands", "dns")) else v
                rows.append(row)
    return rows


def _f(x) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _b(x) -> Optional[bool]:
    if isinstance(x, bool):
        return x
    if x in ("T", "F"):
        return x == "T"
    return None


class ZeekRunner:
    JA3_CANDIDATES = ("packages/ja3", "ja3", "packages")

    def __init__(self, zeek_bin: str = "zeek", timeout: float = 600.0,
                 extra_scripts: Iterable[str] = ()):
        self.bin = zeek_bin
        self.timeout = timeout
        self.extra = list(extra_scripts)
        self.available = shutil.which(zeek_bin) is not None
        self._ja3: Optional[str] = None
        self._ja3_probed = False

    def ja3_script(self) -> Optional[str]:
        """Find a loadable JA3 package (installed via `zkg install ja3`)."""
        if self._ja3_probed:
            return self._ja3
        self._ja3_probed = True
        for cand in self.JA3_CANDIDATES:
            try:
                r = subprocess.run([self.bin, cand, "-e", "event zeek_init() { }"],
                                   capture_output=True, text=True, timeout=60)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if r.returncode == 0:
                self._ja3 = cand
                log.info("Zeek JA3 package loaded via '%s'", cand)
                return cand
        log.warning("Zeek JA3 package not found (zkg install ja3) - using native JA3")
        return None

    def run(self, pcap: str, workdir: str) -> Dict[str, List[dict]]:
        extract_dir = os.path.join(workdir, "extract")
        os.makedirs(extract_dir, exist_ok=True)
        zeek_str = (extract_dir + "/").replace("\\", "\\\\").replace('"', '\\"')
        script = os.path.join(workdir, "email_monitor.zeek")
        with open(script, "w") as fh:
            fh.write(ZEEK_SCRIPT)
            fh.write(f'\nredef LogAscii::use_json = T;\nredef FileExtract::prefix = "{zeek_str}";\n')
        cmd = [self.bin, "-C", "-r", pcap, script]
        ja3 = self.ja3_script()
        if ja3:
            cmd.append(ja3)
        cmd += self.extra
        log.debug("Running: %s", " ".join(cmd))
        r = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True,
                           timeout=self.timeout)
        if r.returncode != 0:
            raise RuntimeError(f"zeek exited {r.returncode}: {r.stderr.strip()[:2000]}")
        logs = {name: read_zeek_log(os.path.join(workdir, f"{name}.log"))
                for name in ("conn", "ssl", "smtp", "files", "x509", "email_cmds")}
        logs["_extract_dir"] = extract_dir  # type: ignore[assignment]
        return logs


# =========================================================================== #
# Facade
# =========================================================================== #
class Dissector:
    """Runs native dissection for every flow, then overlays Zeek results."""

    def __init__(self, engine: str = "auto", zeek_bin: str = "zeek",
                 openssl_bin: str = "openssl", ca_file: Optional[str] = None,
                 workdir: Optional[str] = None, keep_artifacts: bool = False,
                 extra_zeek_scripts: Iterable[str] = ()):
        self.openssl = OpenSSLParser(openssl_bin, ca_file=ca_file)
        self.native = NativeDissector(self.openssl)
        self.zeek = ZeekRunner(zeek_bin, extra_scripts=extra_zeek_scripts)
        if engine == "zeek" and not self.zeek.available:
            raise RuntimeError(f"--engine zeek requested but '{zeek_bin}' is not on PATH")
        self.use_zeek = engine == "zeek" or (engine == "auto" and self.zeek.available)
        if engine == "auto" and not self.zeek.available:
            log.warning("Zeek not found - falling back to the native dissector")
        self.workdir = workdir
        self.keep = keep_artifacts
        self._batch = 0

    @property
    def engine_name(self) -> str:
        return "zeek+native" if self.use_zeek else "native"

    def analyze(self, flows: List[Flow]) -> List[FlowAnalysis]:
        results = [self.native.analyze(f) for f in flows]
        if not (self.use_zeek and flows):
            return results
        self._batch += 1
        base = self.workdir or tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        wd = tempfile.mkdtemp(prefix=f"zeek_batch{self._batch:05d}_", dir=base)
        try:
            pcap = os.path.join(wd, "batch.pcap")
            write_flows_pcap(flows, pcap)
            logs = self.zeek.run(pcap, wd)
            self._merge(flows, results, logs)
        except Exception as e:
            log.error("Zeek batch failed, keeping native results: %s", e)
        finally:
            if self.keep:
                log.info("Zeek artifacts kept in %s", wd)
            else:
                shutil.rmtree(wd, ignore_errors=True)
        return results

    # ------------------------------------------------------------------ #
    def _merge(self, flows: List[Flow], results: List[FlowAnalysis], logs: dict) -> None:
        conn_by_key: Dict[tuple, List[dict]] = {}
        for r in logs["conn"]:
            try:
                a = (r["id.orig_h"], int(r["id.orig_p"]))
                b = (r["id.resp_h"], int(r["id.resp_p"]))
            except (KeyError, ValueError):
                continue
            conn_by_key.setdefault(tuple(sorted((a, b))), []).append(r)

        def by_uid(rows, uid_field="uid"):
            d: Dict[str, List[dict]] = {}
            for r in rows:
                uids = r.get(uid_field)
                if uids is None and "conn_uids" in r:       # Zeek < 5.1 files.log
                    uids = r["conn_uids"]
                for u in (uids if isinstance(uids, list) else [uids]):
                    if u:
                        d.setdefault(u, []).append(r)
            return d

        ssl_by, smtp_by = by_uid(logs["ssl"]), by_uid(logs["smtp"])
        files_by, cmds_by = by_uid(logs["files"]), by_uid(logs["email_cmds"])
        x509_by_fp = {r.get("fingerprint") or r.get("id"): r for r in logs["x509"]}
        by_sha, by_fuid = self._index_extracted(logs["_extract_dir"])

        for flow, res in zip(flows, results):
            cands = conn_by_key.get(flow.key)
            if not cands:
                res.notes.append("no matching Zeek conn record")
                continue
            conn = min(cands, key=lambda r: abs((_f(r.get("ts")) or 0) - flow.start))
            uid = conn.get("uid", "")
            res.engine, res.zeek_uid = "zeek+native", uid
            res.conn_state = conn.get("conn_state", res.conn_state)
            res.duration = _f(conn.get("duration")) or res.duration
            res.orig_bytes = int(_f(conn.get("orig_bytes")) or res.orig_bytes)
            res.resp_bytes = int(_f(conn.get("resp_bytes")) or res.resp_bytes)

            # Module A - email metadata
            em = res.email
            for tx in smtp_by.get(uid, []):
                if tx.get("subject"):
                    em.subjects.append(tx["subject"])
                if tx.get("mailfrom"):
                    em.mail_from.append(tx["mailfrom"])
                em.rcpt_to.extend(tx.get("rcptto") or [])
            em.subjects = list(dict.fromkeys(em.subjects))
            em.mail_from = list(dict.fromkeys(em.mail_from))
            em.rcpt_to = list(dict.fromkeys(em.rcpt_to))
            z_atts = [{"filename": f.get("filename", ""), "mime_type": f.get("mime_type", ""),
                       "size": int(_f(f.get("seen_bytes") or f.get("total_bytes")) or 0)}
                      for f in files_by.get(uid, [])
                      if f.get("source") in ("SMTP", "POP3", "IMAP") and f.get("filename")]
            if z_atts:
                em.attachments = z_atts
            for row in cmds_by.get(uid, []):
                if row.get("commands"):
                    em.commands = [c.upper() for c in row["commands"]]
            em.cleartext_auth = any(c in AUTH_VERBS for c in em.commands)

            # Module B / D - TLS + JA3
            ssl_rows = ssl_by.get(uid, [])
            if ssl_rows:
                s, t = ssl_rows[0], res.tls
                t.observed = True
                t.version = s.get("version") or t.version
                t.cipher = s.get("cipher") or t.cipher
                t.sni = s.get("server_name") or t.sni
                t.validation_status = s.get("validation_status") or t.validation_status
                t.established = _b(s.get("established")) if "established" in s else t.established
                hd = _f(s.get("handshake_duration"))
                t.handshake_duration = hd if hd is not None else t.handshake_duration
                t.ja3 = s.get("ja3") or t.ja3
                t.ja3s = s.get("ja3s") or t.ja3s
                t.starttls = not flow.implicit_tls
                if "sni_matches_cert" in s:
                    t.sni_matches_cert = _b(s["sni_matches_cert"])

                # Module C - leaf certificate via extracted file -> openssl
                fps = s.get("cert_chain_fps") or []
                fuids = s.get("cert_chain_fuids") or []
                t.chain_length = max(t.chain_length, len(fps) or len(fuids))
                leaf_path = (by_sha.get(fps[0].lower()) if fps else None) or \
                            (by_fuid.get(fuids[0]) if fuids else None)
                cert = self.openssl.parse_file(leaf_path) if leaf_path else None
                if cert is None and fps and fps[0] in x509_by_fp:
                    cert = self._cert_from_x509_log(x509_by_fp[fps[0]])
                if cert is not None:
                    res.cert = cert
                    if t.sni and t.sni_matches_cert is None:
                        t.sni_matches_cert = hostname_matches(t.sni, cert)

    @staticmethod
    def _index_extracted(d: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        by_sha, by_fuid = {}, {}
        if not d or not os.path.isdir(d):
            return by_sha, by_fuid
        for name in os.listdir(d):
            p = os.path.join(d, name)
            try:
                if os.path.getsize(p) > 65536:   # certificates are small
                    continue
                with open(p, "rb") as fh:
                    by_sha[hashlib.sha256(fh.read()).hexdigest()] = p
            except OSError:
                continue
            by_fuid[name.rsplit("-", 1)[-1]] = p   # extract-<ts>-<source>-<fuid>
        return by_sha, by_fuid

    @staticmethod
    def _cert_from_x509_log(r: dict) -> CertInfo:
        c = CertInfo(source="zeek-x509.log")
        c.subject = r.get("certificate.subject", "")
        c.issuer = r.get("certificate.issuer", "")
        c.subject_cn, c.issuer_cn = _cn(c.subject), _cn(c.issuer)
        c.not_before = _f(r.get("certificate.not_valid_before"))
        c.not_after = _f(r.get("certificate.not_valid_after"))
        if c.not_before is not None and c.not_after is not None:
            c.lifespan_days = round((c.not_after - c.not_before) / 86400.0, 3)
        c.self_signed = bool(c.subject) and c.subject == c.issuer
        c.key_alg = r.get("certificate.key_alg", "")
        kl = _f(r.get("certificate.key_length"))
        c.key_bits = int(kl) if kl else None
        c.sig_alg = r.get("certificate.sig_alg", "")
        c.san_dns = list(r.get("san.dns") or [])
        c.punycode = any("xn--" in n.lower() for n in [c.subject_cn] + c.san_dns if n)
        c.sha256 = (r.get("fingerprint") or "").lower()
        return c
