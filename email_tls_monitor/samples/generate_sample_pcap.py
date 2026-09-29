#!/usr/bin/env python3
"""
Generate a synthetic email-traffic pcap for demos and regression tests.

Flows produced:
  1. SMTP  587  cleartext AUTH LOGIN + mail with a risky attachment      (FIN)
  2. SMTPS 465  TLS1.2, 3DES, self-signed RSA-1024 10y cert, punycode    (FIN)
  3. IMAPS 993  TLS1.3 ClientHello w/ GREASE (cert not visible)          (RST)
  4. SMTP  25   STARTTLS -> TLS1.2 with CA-issued 90-day RSA-2048 cert   (FIN)
  5. POP3  110  cleartext USER/PASS, never closed                     (timeout)

Usage:  python samples/generate_sample_pcap.py [out.pcap] [certdir]
Requires `openssl` on PATH. Writes test-ca.pem into certdir for --ca-file.
"""
import base64
import os
import struct
import subprocess
import sys
import tempfile
import time

from scapy.all import IP, TCP, Ether, Raw, wrpcap  # type: ignore

T0 = time.time() + 120  # just after cert issuance so validity checks pass


class Session:
    def __init__(self, cip, cport, sip, sport, t, pkts):
        self.c, self.s = (cip, cport), (sip, sport)
        self.cseq, self.sseq = 1000, 5000
        self.t, self.pkts = t, pkts

    def _pkt(self, from_client, flags, payload=b""):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq, ack = (self.cseq, self.sseq) if from_client else (self.sseq, self.cseq)
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1],
                                                       flags=flags, seq=seq, ack=ack)
        if payload:
            p = p / Raw(payload)
        p.time = self.t
        self.t += 0.01
        self.pkts.append(p)
        adv = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        if from_client:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self._pkt(True, "S"); self._pkt(False, "SA"); self._pkt(True, "A")

    def send(self, from_client, data, mss=1200):
        for i in range(0, len(data), mss):
            self._pkt(from_client, "PA", data[i:i + mss])

    def fin(self):
        self._pkt(True, "FA"); self._pkt(False, "FA"); self._pkt(True, "A")

    def rst(self):
        self._pkt(True, "R")


# --- minimal TLS builders --------------------------------------------------- #
def rec(ctype, body, ver=0x0303):
    return struct.pack("!BHH", ctype, ver, len(body)) + body


def hs(mtype, body):
    return struct.pack("!B", mtype) + len(body).to_bytes(3, "big") + body


def ext(t, data):
    return struct.pack("!HH", t, len(data)) + data


def client_hello(sni, ciphers, groups, versions=None, grease=False):
    exts = b""
    if grease:
        exts += ext(0x0A0A, b"")
    name = sni.encode()
    exts += ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    g = struct.pack(f"!{len(groups)}H", *groups)
    exts += ext(10, struct.pack("!H", len(g)) + g)
    exts += ext(11, b"\x01\x00")
    if versions:
        v = struct.pack(f"!{len(versions)}H", *versions)
        exts += ext(43, bytes([len(v)]) + v)
    cs = struct.pack(f"!{len(ciphers)}H", *ciphers)
    body = (struct.pack("!H", 0x0303) + os.urandom(32) + b"\x00" + struct.pack("!H", len(cs)) + cs
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    return rec(22, hs(1, body), 0x0301)


def server_hello(cipher, tls13=False):
    exts = ext(0xFF01, b"\x00")
    if tls13:
        exts += ext(43, struct.pack("!H", 0x0304))
    body = (struct.pack("!H", 0x0303) + os.urandom(32) + b"\x00" + struct.pack("!HB", cipher, 0)
            + struct.pack("!H", len(exts)) + exts)
    return hs(2, body)


def certificate(ders):
    lst = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    return hs(11, len(lst).to_bytes(3, "big") + lst)


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def make_certs(d):
    # self-signed, 10 years, RSA-1024, punycode CN
    openssl("req", "-x509", "-newkey", "rsa:1024", "-nodes", "-keyout", "ss.key", "-out", "ss.der",
            "-outform", "DER", "-days", "3650", "-subj", "/CN=xn--pple-43d.com", cwd=d)
    # test CA + 90-day leaf with SAN
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "test-ca.pem",
            "-days", "3650", "-subj", "/CN=SIH Test Root CA/O=SIH Lab",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
            cwd=d)
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
            "-subj", "/CN=mail.example.com", cwd=d)
    with open(os.path.join(d, "ext.cnf"), "w") as fh:
        fh.write("subjectAltName=DNS:mail.example.com,DNS:smtp.example.com\n")
    openssl("x509", "-req", "-in", "leaf.csr", "-CA", "test-ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "90", "-extfile", "ext.cnf", "-outform", "DER",
            "-out", "leaf.der", cwd=d)
    openssl("x509", "-in", "test-ca.pem", "-outform", "DER", "-out", "ca.der", cwd=d)
    rd = lambda n: open(os.path.join(d, n), "rb").read()
    return rd("ss.der"), rd("leaf.der"), rd("ca.der")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_email.pcap"
    certdir = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="certs_")
    os.makedirs(certdir, exist_ok=True)
    ss, leaf, ca = make_certs(certdir)
    pkts = []

    # 1. SMTP submission, cleartext auth, risky attachment
    s = Session("10.0.0.5", 50001, "10.0.0.25", 587, T0, pkts)
    s.handshake()
    s.send(False, b"220 mx.lab ESMTP\r\n")
    msg = (b"From: a@lab\r\nTo: b@lab\r\nSubject: Urgent invoice 7Qx9ZkP3mW8vR2tY5nB1cL4\r\n"
           b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n"
           b"--XX\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n"
           b"--XX\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(b"MZ" + b"\x00" * 300)
           + b"\r\n--XX--\r\n")
    for c in (b"EHLO client\r\n", b"AUTH LOGIN\r\n", base64.b64encode(b"alice") + b"\r\n",
              base64.b64encode(b"hunter2") + b"\r\n", b"MAIL FROM:<a@lab>\r\n",
              b"RCPT TO:<b@lab>\r\n", b"DATA\r\n"):
        s.send(True, c); s.send(False, b"250 ok\r\n")
    s.send(True, msg + b"\r\n.\r\n"); s.send(False, b"250 queued\r\n")
    s.send(True, b"QUIT\r\n"); s.fin()

    # 2. SMTPS: TLS1.2, 3DES, self-signed RSA-1024 10y, punycode
    s = Session("10.0.0.6", 50002, "203.0.113.9", 465, T0 + 1, pkts)
    s.handshake()
    s.send(True, client_hello("xn--pple-43d.com", [0xC02F, 0x000A, 0x0035], [23, 24]))
    s.send(False, rec(22, server_hello(0x000A) + certificate([ss]) + hs(14, b"")))
    s.send(True, rec(22, hs(16, os.urandom(130))) + rec(20, b"\x01") + rec(22, os.urandom(40)))
    s.t += 0.08
    s.send(False, rec(20, b"\x01") + rec(22, os.urandom(40)))
    s.send(True, rec(23, os.urandom(64)))
    s.send(False, rec(23, os.urandom(200)))
    s.fin()

    # 3. IMAPS TLS1.3 with GREASE
    s = Session("10.0.0.7", 50003, "198.51.100.20", 993, T0 + 2, pkts)
    s.handshake()
    s.send(True, client_hello("imap.gmail.com", [0x1A1A, 0x1301, 0x1302, 0xC02B],
                              [0x2A2A, 29, 23], versions=[0x0304, 0x0303], grease=True))
    s.send(False, rec(22, server_hello(0x1301, tls13=True)) + rec(20, b"\x01")
           + rec(23, os.urandom(900)))
    s.t += 0.05
    s.send(True, rec(20, b"\x01") + rec(23, os.urandom(53)))
    s.send(False, rec(23, os.urandom(300)))
    s.rst()

    # 4. SMTP STARTTLS on 25, CA-issued leaf
    s = Session("10.0.0.8", 50004, "192.0.2.50", 25, T0 + 3, pkts)
    s.handshake()
    s.send(False, b"220 mail.example.com ESMTP\r\n")
    s.send(True, b"EHLO relay.lab\r\n"); s.send(False, b"250-mail.example.com\r\n250 STARTTLS\r\n")
    s.send(True, b"STARTTLS\r\n"); s.send(False, b"220 2.0.0 Ready to start TLS\r\n")
    s.send(True, client_hello("mail.example.com", [0xC02F, 0xC030], [29, 23]))
    s.send(False, rec(22, server_hello(0xC02F) + certificate([leaf, ca]) + hs(14, b"")))
    s.send(True, rec(22, hs(16, os.urandom(66))) + rec(20, b"\x01") + rec(22, os.urandom(40)))
    s.t += 0.03
    s.send(False, rec(20, b"\x01") + rec(22, os.urandom(40)))
    s.send(True, rec(23, os.urandom(120)))
    s.fin()

    # 5. POP3 cleartext, left open -> timeout
    s = Session("10.0.0.9", 50005, "10.0.0.110", 110, T0 + 4, pkts)
    s.handshake()
    s.send(False, b"+OK POP3 ready\r\n")
    for c in (b"USER bob\r\n", b"PASS secret\r\n", b"STAT\r\n"):
        s.send(True, c); s.send(False, b"+OK\r\n")

    pkts.sort(key=lambda p: p.time)
    wrpcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out}; test CA at {os.path.join(certdir, 'test-ca.pem')}")


if __name__ == "__main__":
    main()
