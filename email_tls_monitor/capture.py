"""
capture.py - Packet ingestion, email-protocol filtering and bidirectional
TCP flow reassembly.

Two ingestion modes share one FlowTracker:
  * LiveCapture  - Scapy AsyncSniffer on an interface (needs root/CAP_NET_RAW)
  * iter_pcap    - streaming reader for .pcap / .pcapng files

A flow is completed when:
  * a RST is seen, or
  * FINs have been seen from BOTH directions, or
  * no packet arrived for `timeout` seconds (idle expiry), or
  * the source ends (flush).
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from scapy.all import IP, TCP, AsyncSniffer, PcapReader, PcapWriter  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Email port map
# --------------------------------------------------------------------------- #
# port -> (protocol family, implicit TLS?)
EMAIL_PORTS: Dict[int, Tuple[str, bool]] = {
    25: ("SMTP", False),
    587: ("SMTP", False),   # submission, usually STARTTLS
    465: ("SMTP", True),    # SMTPS (implicit TLS, RFC 8314)
    143: ("IMAP", False),
    993: ("IMAP", True),
    110: ("POP3", False),
    995: ("POP3", True),
}

EMAIL_BPF = "tcp and (" + " or ".join(f"port {p}" for p in sorted(EMAIL_PORTS)) + ")"

# TCP flag bits
_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10

Endpoint = Tuple[str, int]
FlowKey = Tuple[Endpoint, Endpoint]  # canonical (sorted) endpoint pair


def _l3(pkt):
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def is_email_packet(pkt) -> bool:
    """Cheap Python-side filter (used for offline files; BPF is used live)."""
    if TCP not in pkt or _l3(pkt) is None:
        return False
    t = pkt[TCP]
    return t.sport in EMAIL_PORTS or t.dport in EMAIL_PORTS


def canonical_key(a: Endpoint, b: Endpoint) -> FlowKey:
    return (a, b) if a <= b else (b, a)


# --------------------------------------------------------------------------- #
# Flow object
# --------------------------------------------------------------------------- #
@dataclass
class Flow:
    flow_id: str
    orig: Endpoint                 # client
    resp: Endpoint                 # server (the email port side)
    protocol: str                  # SMTP / IMAP / POP3
    implicit_tls: bool
    start: float
    last_seen: float
    packets: list = field(default_factory=list, repr=False)
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_bytes: int = 0            # TCP payload bytes client -> server
    resp_bytes: int = 0            # TCP payload bytes server -> client
    saw_syn: bool = False
    fin_orig: bool = False
    fin_resp: bool = False
    rst: bool = False
    truncated: bool = False        # packet cap reached; stats still counted
    close_reason: str = ""

    @property
    def key(self) -> FlowKey:
        return canonical_key(self.orig, self.resp)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start)

    @property
    def server_port(self) -> int:
        return self.resp[1]

    def summary(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "implicit_tls": self.implicit_tls,
            "orig_h": self.orig[0], "orig_p": self.orig[1],
            "resp_h": self.resp[0], "resp_p": self.resp[1],
            "start": self.start,
            "duration": round(self.duration, 6),
            "orig_pkts": self.orig_pkts, "resp_pkts": self.resp_pkts,
            "orig_bytes": self.orig_bytes, "resp_bytes": self.resp_bytes,
            "close_reason": self.close_reason,
            "truncated": self.truncated,
        }


# --------------------------------------------------------------------------- #
# Flow tracker
# --------------------------------------------------------------------------- #
class FlowTracker:
    """Groups packets into bidirectional TCP sessions keyed on the 5-tuple.

    Not thread-safe by itself; LiveCapture wraps it in a lock.
    """

    def __init__(self, timeout: float = 4.0, max_packets_per_flow: int = 50_000):
        self.timeout = float(timeout)
        self.max_packets = int(max_packets_per_flow)
        self._flows: Dict[FlowKey, Flow] = {}
        # recently closed keys -> close time, to swallow trailing ACK/FIN/RST
        self._closed: Dict[FlowKey, float] = {}
        self._counter = 0
        self.packets_seen = 0

    def __len__(self) -> int:
        return len(self._flows)

    # -- helpers ---------------------------------------------------------- #
    def _new_flow(self, src: Endpoint, dst: Endpoint, flags: int, ts: float) -> Optional[Flow]:
        # Decide who is the client. SYN without ACK is authoritative,
        # otherwise the side on a well-known email port is the server.
        if flags & _SYN and not flags & _ACK:
            orig, resp = src, dst
        elif dst[1] in EMAIL_PORTS and src[1] not in EMAIL_PORTS:
            orig, resp = src, dst
        elif src[1] in EMAIL_PORTS and dst[1] not in EMAIL_PORTS:
            orig, resp = dst, src
        else:  # both/neither on email ports: lower port = server
            orig, resp = (src, dst) if dst[1] <= src[1] else (dst, src)
        if resp[1] not in EMAIL_PORTS:
            return None
        proto, implicit = EMAIL_PORTS[resp[1]]
        self._counter += 1
        return Flow(
            flow_id=f"F{self._counter:07d}",
            orig=orig, resp=resp, protocol=proto, implicit_tls=implicit,
            start=ts, last_seen=ts,
        )

    def _finish(self, key: FlowKey, reason: str) -> Flow:
        flow = self._flows.pop(key)
        flow.close_reason = reason
        self._closed[key] = flow.last_seen
        return flow

    # -- public API ------------------------------------------------------- #
    def process(self, pkt, ts: Optional[float] = None) -> List[Flow]:
        """Feed one packet; returns flows completed by this packet (FIN/RST)."""
        l3 = _l3(pkt)
        if l3 is None or TCP not in pkt:
            return []
        tcp = pkt[TCP]
        ts = float(ts if ts is not None else pkt.time)
        flags = int(tcp.flags)
        src: Endpoint = (str(l3.src), int(tcp.sport))
        dst: Endpoint = (str(l3.dst), int(tcp.dport))
        key = canonical_key(src, dst)
        payload_len = len(bytes(tcp.payload))
        self.packets_seen += 1

        flow = self._flows.get(key)
        if flow is None:
            closed_at = self._closed.get(key)
            is_new_syn = bool(flags & _SYN) and not flags & _ACK
            if closed_at is not None and not is_new_syn and payload_len == 0 \
                    and ts - closed_at <= 2 * self.timeout:
                return []  # straggler of a finished session
            flow = self._new_flow(src, dst, flags, ts)
            if flow is None:
                return []
            self._flows[key] = flow
            self._closed.pop(key, None)

        from_orig = src == flow.orig
        flow.last_seen = max(flow.last_seen, ts)
        if flags & _SYN:
            flow.saw_syn = True
        if from_orig:
            flow.orig_pkts += 1
            flow.orig_bytes += payload_len
        else:
            flow.resp_pkts += 1
            flow.resp_bytes += payload_len

        if len(flow.packets) < self.max_packets:
            flow.packets.append(pkt)
        else:
            flow.truncated = True

        if flags & _RST:
            flow.rst = True
            return [self._finish(key, "rst")]
        if flags & _FIN:
            if from_orig:
                flow.fin_orig = True
            else:
                flow.fin_resp = True
            if flow.fin_orig and flow.fin_resp:
                return [self._finish(key, "fin")]
        return []

    def expire(self, now: float) -> List[Flow]:
        """Complete flows idle for longer than `timeout` seconds."""
        done = [k for k, f in self._flows.items() if now - f.last_seen >= self.timeout]
        out = [self._finish(k, "timeout") for k in done]
        horizon = now - 2 * self.timeout
        for k in [k for k, t in self._closed.items() if t < horizon]:
            del self._closed[k]
        return out

    def flush(self) -> List[Flow]:
        return [self._finish(k, "flush") for k in list(self._flows)]


# --------------------------------------------------------------------------- #
# Offline ingestion
# --------------------------------------------------------------------------- #
def iter_pcap(path: str) -> Iterator:
    """Stream email-port packets from a .pcap/.pcapng (auto-detected)."""
    with PcapReader(path) as reader:  # PcapReader switches to pcapng if needed
        for pkt in reader:
            if is_email_packet(pkt):
                yield pkt


def flows_from_pcap(path: str, tracker: FlowTracker,
                    dump: Optional["PacketDumper"] = None,
                    sweep_every: float = 1.0) -> Iterator[Flow]:
    """Yield completed flows from an offline capture, using packet time as clock."""
    last_sweep = None
    for pkt in iter_pcap(path):
        ts = float(pkt.time)
        if dump:
            dump.write(pkt)
        yield from tracker.process(pkt, ts)
        if last_sweep is None:
            last_sweep = ts
        elif ts - last_sweep >= sweep_every:
            yield from tracker.expire(ts)
            last_sweep = ts
    yield from tracker.flush()


# --------------------------------------------------------------------------- #
# Live ingestion
# --------------------------------------------------------------------------- #
class LiveCapture:
    """Background sniffer that pushes completed flows to a callback.

    Requires root / CAP_NET_RAW (Linux) or Npcap (Windows).
    """

    def __init__(self, interface: str, tracker: FlowTracker,
                 on_flow: Callable[[Flow], None],
                 bpf: str = EMAIL_BPF, dump: Optional["PacketDumper"] = None,
                 sweep_interval: float = 1.0):
        self.interface = interface
        self.tracker = tracker
        self.on_flow = on_flow
        self.bpf = bpf
        self.dump = dump
        self.sweep_interval = sweep_interval
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer: Optional[AsyncSniffer] = None
        self._sweeper: Optional[threading.Thread] = None

    def _on_packet(self, pkt) -> None:
        with self._lock:
            if self.dump:
                self.dump.write(pkt)
            done = self.tracker.process(pkt, float(pkt.time))
        for f in done:
            self.on_flow(f)

    def _sweep_loop(self) -> None:
        while not self._stop.wait(self.sweep_interval):
            with self._lock:
                done = self.tracker.expire(time.time())
            for f in done:
                self.on_flow(f)

    def start(self) -> None:
        kwargs = {"filter": self.bpf}
        try:  # kernel BPF needs libpcap to compile; fall back to Python filtering
            from scapy.arch.common import compile_filter  # type: ignore
            compile_filter(self.bpf, iface=self.interface)
            log.info("Sniffing on %s with BPF: %s", self.interface, self.bpf)
        except Exception as e:
            log.warning("BPF unavailable (%s) - filtering in Python (slower)", e)
            kwargs = {"lfilter": is_email_packet}
        self._sniffer = AsyncSniffer(iface=self.interface, prn=self._on_packet,
                                     store=False, **kwargs)
        self._sniffer.start()
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True,
                                         name="flow-sweeper")
        self._sweeper.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
        if self._sweeper:
            self._sweeper.join(timeout=2)
        with self._lock:
            done = self.tracker.flush()
        for f in done:
            self.on_flow(f)


# --------------------------------------------------------------------------- #
# pcap dumping
# --------------------------------------------------------------------------- #
class PacketDumper:
    """Append packets to a pcap as they arrive (e.g. --dump-pcap)."""

    def __init__(self, path: str):
        self.path = path
        self._w = PcapWriter(path, append=False, sync=True)

    def write(self, pkt) -> None:
        self._w.write(pkt)

    def close(self) -> None:
        self._w.close()


def write_flows_pcap(flows: Iterable[Flow], path: str) -> int:
    """Write all packets of the given flows, time-ordered, into one pcap."""
    pkts = sorted((p for f in flows for p in f.packets), key=lambda p: float(p.time))
    w = PcapWriter(path, append=False, sync=False)
    try:
        for p in pkts:
            w.write(p)
    finally:
        w.close()
    return len(pkts)
