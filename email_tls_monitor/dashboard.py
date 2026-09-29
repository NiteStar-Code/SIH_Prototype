#!/usr/bin/env python3
"""
dashboard.py - Web UI for the Email TLS Security Monitor.

Runs the same pipeline as app.py (capture -> dissect -> features -> score) and
streams every scored flow to a browser dashboard over Server-Sent Events.
Standard library only: no Flask, no CDN, so it works offline on hackathon Wi-Fi.

  python dashboard.py                        # open http://127.0.0.1:8080, click "Demo"
  python dashboard.py --pcap capture.pcap    # start by analysing a file
  sudo .venv/bin/python dashboard.py --interface wlan0   # start live capture

Sources can also be switched from the UI (demo replay / pcap upload / live).
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import queue
import random
import subprocess
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional

from app import Pipeline
from capture import EMAIL_PORTS, FlowTracker, LiveCapture, flows_from_pcap
from dissector import Dissector
from features import FeatureExtractor
from model import ThreatScorer

log = logging.getLogger("dashboard")
HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "web")
MAX_RECORDS = 5000


# --------------------------------------------------------------------------- #
# Event hub: keeps history + fans out to SSE subscribers
# --------------------------------------------------------------------------- #
class Hub:
    def __init__(self):
        self._lock = threading.Lock()
        self._subs: List[queue.Queue] = []
        self.records: List[dict] = []
        self.status: dict = {"mode": "idle", "detail": "", "packets": 0,
                             "open_flows": 0, "error": ""}

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=10000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def _broadcast(self, event: str, data) -> None:
        msg = (event, json.dumps(data, default=str))
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def add_record(self, rec: dict) -> None:
        with self._lock:
            self.records.append(rec)
            if len(self.records) > MAX_RECORDS:
                del self.records[: len(self.records) - MAX_RECORDS]
        self._broadcast("flow", rec)

    def set_status(self, **kw) -> None:
        with self._lock:
            self.status.update(kw)
            st = dict(self.status)
        self._broadcast("status", st)

    def clear(self) -> None:
        with self._lock:
            self.records.clear()
        self._broadcast("clear", {})


class HubSink:
    """Pipeline sink that feeds the hub (and optionally a JSONL file)."""

    def __init__(self, hub: Hub, source: str, jsonl: Optional[str] = None):
        self.hub, self.source = hub, source
        self._fh = open(jsonl, "a", encoding="utf-8") if jsonl else None

    def write(self, rec: dict) -> None:
        rec["source"] = self.source
        rec["seen_at"] = time.time()
        self.hub.add_record(rec)
        if self._fh:
            self._fh.write(json.dumps(rec, default=str) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()


# --------------------------------------------------------------------------- #
# Controller: one active source at a time
# --------------------------------------------------------------------------- #
class Controller:
    def __init__(self, args, hub: Hub):
        self.args, self.hub = args, hub
        self.extractor = FeatureExtractor(normalize=True)
        self.scorer = ThreatScorer(args.model, extractor=self.extractor,
                                   thresholds=tuple(args.thresholds))
        self.dissector = Dissector(engine=args.engine, ca_file=args.ca_file)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._demo_recs: Optional[List[dict]] = None

    # -- info ---------------------------------------------------------- #
    def info(self) -> dict:
        try:
            from scapy.all import get_if_list  # type: ignore
            ifaces = get_if_list()
        except Exception:
            ifaces = []
        return {
            "engine": self.dissector.engine_name,
            "scorer": self.scorer.scorer_name,
            "features": self.extractor.feature_names,
            "thresholds": list(self.args.thresholds),
            "ports": {str(p): v[0] + (" (TLS)" if v[1] else "")
                      for p, v in sorted(EMAIL_PORTS.items())},
            "interfaces": ifaces,
            "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
        }

    # -- lifecycle ----------------------------------------------------- #
    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=5)
        self._thread = None

    def _start(self, mode: str, detail: str, target, *a) -> None:
        with self._lock:
            self.stop()
            self._stop = threading.Event()
            self.hub.set_status(mode=mode, detail=detail, packets=0,
                                open_flows=0, error="")

            def runner():
                try:
                    target(self._stop, *a)
                    if self.hub.status["mode"] == mode:
                        self.hub.set_status(mode="idle", detail=f"{detail} - finished")
                except Exception as e:  # surface every failure in the UI
                    log.exception("%s failed", mode)
                    msg = str(e)
                    if isinstance(e, PermissionError):
                        msg = ("Permission denied - live capture needs root. Run: sudo "
                               f"{sys.executable} dashboard.py")
                    self.hub.set_status(mode="idle", detail="", error=msg)
            self._thread = threading.Thread(target=runner, daemon=True, name=mode)
            self._thread.start()

    def _pipeline(self, source: str) -> Pipeline:
        return Pipeline(self.dissector, self.extractor, self.scorer,
                        HubSink(self.hub, source, self.args.output))

    # -- sources ------------------------------------------------------- #
    def start_pcap(self, path: str, label: str) -> None:
        self._start("pcap", label, self._run_pcap, path, label)

    def _run_pcap(self, stop: threading.Event, path: str, label: str) -> None:
        pipe = self._pipeline(f"pcap:{label}")
        tracker = FlowTracker(timeout=self.args.timeout)
        batch = []
        for flow in flows_from_pcap(path, tracker):
            if stop.is_set():
                return
            batch.append(flow)
            if len(batch) >= 25:
                pipe.process(batch)
                batch = []
                self.hub.set_status(packets=tracker.packets_seen)
        pipe.process(batch)
        pipe.sink.close()
        self.hub.set_status(packets=tracker.packets_seen)

    def start_live(self, iface: str) -> None:
        self._start("live", iface, self._run_live, iface)

    def _run_live(self, stop: threading.Event, iface: str) -> None:
        pipe = self._pipeline(f"live:{iface}")
        tracker = FlowTracker(timeout=self.args.timeout)
        q: queue.Queue = queue.Queue()
        cap = LiveCapture(iface, tracker, on_flow=q.put)
        cap.start()  # raises on bad interface / missing privileges
        batch, last, last_status = [], time.monotonic(), 0.0
        try:
            while not stop.is_set():
                try:
                    batch.append(q.get(timeout=0.5))
                except queue.Empty:
                    pass
                cap.check()
                now = time.monotonic()
                if batch and (len(batch) >= 50 or now - last >= 2.0):
                    pipe.process(batch)
                    batch, last = [], now
                if now - last_status >= 1.0:
                    self.hub.set_status(packets=tracker.packets_seen, open_flows=len(tracker))
                    last_status = now
        finally:
            cap.stop()
            while not q.empty():
                batch.append(q.get_nowait())
            pipe.process(batch)
            pipe.sink.close()

    def start_demo(self) -> None:
        self._start("demo", "sample capture replay", self._run_demo)

    def _demo_records(self) -> List[dict]:
        """Analyse the bundled sample pcap once, for real, and cache the output."""
        if self._demo_recs is None:
            d = tempfile.mkdtemp(prefix="emailmon_demo_")
            pcap, certs = os.path.join(d, "demo.pcap"), os.path.join(d, "certs")
            subprocess.run([sys.executable, os.path.join(HERE, "samples", "generate_sample_pcap.py"),
                            pcap, certs], check=True, capture_output=True)
            ca = os.path.join(certs, "test-ca.pem")
            dis = Dissector(engine=self.args.engine,
                            ca_file=ca if os.path.exists(ca) else self.args.ca_file)
            out: List[dict] = []

            class _Collect:
                def write(self, rec):
                    out.append(rec)
            Pipeline(dis, self.extractor, self.scorer, _Collect()).process(
                list(flows_from_pcap(pcap, FlowTracker(timeout=self.args.timeout))))
            self._demo_recs = out
        return self._demo_recs

    def _run_demo(self, stop: threading.Event) -> None:
        base = self._demo_records()
        sink = HubSink(self.hub, "demo")
        n = 0
        while not stop.is_set():
            order = base[:]
            random.shuffle(order)
            for r in order:
                if stop.wait(random.uniform(0.9, 2.2)):
                    return
                rec = copy.deepcopy(r)
                n += 1
                fl = rec["flow"]
                fl["flow_id"] = f"D{n:06d}"
                fl["orig_p"] = random.randint(40000, 65000)
                fl["start"] = time.time()
                sink.write(rec)
                self.hub.set_status(packets=self.hub.status.get("packets", 0)
                                    + fl["orig_pkts"] + fl["resp_pkts"])


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def make_handler(ctl: Controller, hub: Hub):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):
            log.debug("%s - " + fmt, self.address_string(), *a)

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        # -- GET ------------------------------------------------------- #
        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            if path == "/api/info":
                return self._json(ctl.info())
            if path == "/api/state":
                return self._json({"status": hub.status, "records": hub.records})
            if path == "/api/events":
                return self._sse()
            if path == "/api/export":
                body = "".join(json.dumps(r, default=str) + "\n" for r in hub.records).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Disposition", 'attachment; filename="ratings.jsonl"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            self._send(404, b"not found", "text/plain")

        def _sse(self):
            q = hub.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(b"event: status\ndata: " + json.dumps(hub.status).encode() + b"\n\n")
                self.wfile.flush()
                while True:
                    try:
                        ev, data = q.get(timeout=15)
                        self.wfile.write(f"event: {ev}\ndata: {data}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                hub.unsubscribe(q)

        # -- POST ------------------------------------------------------ #
        def do_POST(self):
            path = self.path.split("?")[0]
            try:
                if path == "/api/demo":
                    ctl.start_demo()
                elif path == "/api/live":
                    iface = (json.loads(self._body() or b"{}").get("interface") or "").strip()
                    if not iface:
                        return self._json({"error": "interface required"}, 400)
                    ctl.start_live(iface)
                elif path == "/api/pcap":
                    name = os.path.basename(self.headers.get("X-Filename") or "upload.pcap")
                    data = self._body()
                    if not data:
                        return self._json({"error": "empty upload"}, 400)
                    fd, tmp = tempfile.mkstemp(prefix="emailmon_", suffix="_" + name)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(data)
                    ctl.start_pcap(tmp, name)
                elif path == "/api/stop":
                    ctl.stop()
                    hub.set_status(mode="idle", detail="stopped")
                elif path == "/api/clear":
                    hub.clear()
                else:
                    return self._send(404, b"not found", "text/plain")
                self._json({"ok": True})
            except Exception as e:
                log.exception("request failed")
                self._json({"error": str(e)}, 500)
    return H


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Web dashboard for the Email TLS Security Monitor")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--model", "-m", help="pre-trained model (.joblib/.onnx); heuristic if omitted")
    p.add_argument("--engine", choices=("auto", "zeek", "native"), default="auto")
    p.add_argument("--ca-file", help="CA bundle for `openssl verify`")
    p.add_argument("--timeout", type=float, default=4.0, help="flow idle timeout, seconds")
    p.add_argument("--thresholds", type=float, nargs=2, default=(0.35, 0.75))
    p.add_argument("--output", "-o", help="also append every scored flow to this JSONL file")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--interface", "-i", help="start live capture on this interface")
    src.add_argument("--pcap", "-r", help="start by analysing this pcap")
    src.add_argument("--demo", action="store_true", help="start the demo replay immediately")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    hub = Hub()
    ctl = Controller(args, hub)
    if args.interface:
        ctl.start_live(args.interface)
    elif args.pcap:
        ctl.start_pcap(args.pcap, os.path.basename(args.pcap))
    elif args.demo:
        ctl.start_demo()

    srv = ThreadingHTTPServer((args.host, args.port), make_handler(ctl, hub))
    srv.daemon_threads = True
    log.info("Dashboard on http://%s:%d  (engine=%s, scorer=%s)", args.host, args.port,
             ctl.dissector.engine_name, ctl.scorer.scorer_name)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctl.stop()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
