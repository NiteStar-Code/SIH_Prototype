#!/usr/bin/env python3
"""
app.py - CLI entrypoint.

Examples
  python app.py --pcap capture.pcapng --output ratings.jsonl
  sudo python app.py --interface eth0 --model model.joblib --output live.jsonl
"""
from __future__ import annotations

import argparse
import json
import logging
import queue
import signal
import sys
import time
from collections import Counter
from typing import List, Optional, TextIO

from capture import EMAIL_PORTS, FlowTracker, LiveCapture, PacketDumper, flows_from_pcap, Flow
from dissector import Dissector
from features import FeatureExtractor
from model import ThreatScorer

log = logging.getLogger("emailmon")


# --------------------------------------------------------------------------- #
# Output sink
# --------------------------------------------------------------------------- #
class Sink:
    """JSON Lines by default; a *.json path gets a single JSON array at close."""

    def __init__(self, path: Optional[str]):
        self.path = path
        self.as_array = bool(path and path.endswith(".json"))
        self._buf: List[dict] = []
        self._fh: TextIO = sys.stdout if path in (None, "-") else open(path, "w", encoding="utf-8")
        self.counts: Counter = Counter()

    def write(self, rec: dict) -> None:
        self.counts[rec["rating"]["classification"]] += 1
        if self.as_array:
            self._buf.append(rec)
        else:
            self._fh.write(json.dumps(rec, default=str) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self.as_array:
            json.dump(self._buf, self._fh, indent=2, default=str)
            self._fh.write("\n")
        if self._fh is not sys.stdout:
            self._fh.close()


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
class Pipeline:
    def __init__(self, dissector: Dissector, extractor: FeatureExtractor,
                 scorer: ThreatScorer, sink: Sink, include_vector: bool = True):
        self.dissector = dissector
        self.extractor = extractor
        self.scorer = scorer
        self.sink = sink
        self.include_vector = include_vector
        self.flows_done = 0

    def process(self, flows: List[Flow]) -> None:
        if not flows:
            return
        analyses = self.dissector.analyze(flows)
        X = self.extractor.transform_batch(analyses)
        ratings = self.scorer.score_batch(X, analyses)
        for a, x, r in zip(analyses, X, ratings):
            rec = {
                "flow": a.flow,
                "engine": a.engine,
                "zeek_uid": a.zeek_uid,
                "conn_state": a.conn_state,
                "tls": vars(a.tls),
                "certificate": vars(a.cert) if a.cert else None,
                "email": vars(a.email),
                "features": {k: round(v, 6) for k, v in self.extractor.raw_features(a).items()},
                "rating": r.to_dict(self.scorer.top_k),
                "notes": a.notes,
            }
            if self.include_vector:
                rec["vector"] = [round(float(v), 6) for v in x]
            self.sink.write(rec)
            fl = a.flow
            lvl = logging.WARNING if r.classification != "BENIGN" else logging.INFO
            log.log(lvl, "[%-10s %.2f] %s %s:%s -> %s:%s %s",
                    r.classification, r.probability, fl["protocol"], fl["orig_h"],
                    fl["orig_p"], fl["resp_h"], fl["resp_p"],
                    ",".join(i.signal for i in r.indicators[:3]) or "-")
        self.flows_done += len(flows)


def run_offline(args, pipeline: Pipeline, dump: Optional[PacketDumper]) -> None:
    tracker = FlowTracker(timeout=args.timeout, max_packets_per_flow=args.max_packets)
    batch: List[Flow] = []
    for flow in flows_from_pcap(args.pcap, tracker, dump=dump):
        batch.append(flow)
        if len(batch) >= args.batch_size:
            pipeline.process(batch)
            batch = []
    pipeline.process(batch)
    log.info("Read %d email packets", tracker.packets_seen)


def run_live(args, pipeline: Pipeline, dump: Optional[PacketDumper]) -> None:
    tracker = FlowTracker(timeout=args.timeout, max_packets_per_flow=args.max_packets)
    q: "queue.Queue[Flow]" = queue.Queue()
    cap = LiveCapture(args.interface, tracker, on_flow=q.put, dump=dump)
    stop = {"flag": False}

    def _sig(*_):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    cap.start()
    log.info("Capturing on '%s' - watching TCP ports %s", args.interface,
             ",".join(str(p) for p in sorted(EMAIL_PORTS)))
    batch: List[Flow] = []
    last = time.monotonic()
    next_status = time.monotonic() + args.status_interval
    seen_at_status = 0
    deadline = time.monotonic() + args.duration if args.duration else None
    try:
        while not stop["flag"] and (deadline is None or time.monotonic() < deadline):
            try:
                batch.append(q.get(timeout=0.5))
            except queue.Empty:
                pass
            cap.check()  # re-raise if the sniffer thread died
            if args.status_interval and time.monotonic() >= next_status:
                seen = tracker.packets_seen
                if seen == seen_at_status:
                    log.warning("No SMTP/IMAP/POP3 packets seen in the last %.0fs on '%s'. "
                                "Is this the right interface, and is a mail client (not webmail "
                                "over HTTPS/443) actually talking on these ports?",
                                args.status_interval, args.interface)
                else:
                    log.info("Status: %d email packets, %d open flows, %d flows scored",
                             seen, len(tracker), pipeline.flows_done)
                seen_at_status = seen
                next_status = time.monotonic() + args.status_interval
            if batch and (len(batch) >= args.batch_size
                          or time.monotonic() - last >= args.batch_interval):
                pipeline.process(batch)
                batch, last = [], time.monotonic()
    finally:
        log.info("Stopping capture, flushing open flows...")
        cap.stop()
        while not q.empty():
            batch.append(q.get_nowait())
        pipeline.process(batch)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Email (SMTP/IMAP/POP3) TLS security monitor: Zeek + OpenSSL + ML scoring")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", "-i", help="live capture interface (needs root/CAP_NET_RAW)")
    src.add_argument("--pcap", "-r", help="offline .pcap/.pcapng file")
    p.add_argument("--model", "-m", help="pre-trained model (.joblib or .onnx); heuristic if omitted")
    p.add_argument("--output", "-o", default="-", help="output path (.jsonl streaming, .json array, '-' stdout)")
    p.add_argument("--engine", choices=("auto", "zeek", "native"), default="auto",
                   help="dissection engine (default: zeek if installed, else native)")
    p.add_argument("--timeout", type=float, default=4.0, help="flow inactivity timeout, seconds (default 4)")
    p.add_argument("--batch-size", type=int, default=200, help="flows per Zeek batch")
    p.add_argument("--batch-interval", type=float, default=10.0, help="live mode: max seconds between batches")
    p.add_argument("--duration", type=float, default=0, help="live mode: stop after N seconds (0 = until Ctrl-C)")
    p.add_argument("--status-interval", type=float, default=30.0,
                   help="live mode: log a capture status line every N seconds (0 = off)")
    p.add_argument("--max-packets", type=int, default=50_000, help="per-flow packet retention cap")
    p.add_argument("--dump-pcap", help="also write all captured email packets to this pcap")
    p.add_argument("--workdir", help="where Zeek batch directories are created")
    p.add_argument("--keep-artifacts", action="store_true", help="keep Zeek logs/extracted files")
    p.add_argument("--zeek-bin", default="zeek")
    p.add_argument("--openssl-bin", default="openssl")
    p.add_argument("--ca-file", help="CA bundle for `openssl verify` (native engine)")
    p.add_argument("--ja3-mode", choices=("scalar", "embedding"), default="scalar")
    p.add_argument("--ja3-dim", type=int, default=8, help="embedding width when --ja3-mode embedding")
    p.add_argument("--no-normalize", action="store_true", help="disable log1p scaling of heavy-tailed features")
    p.add_argument("--ja3-blocklist", help="file with one JA3/JA3S md5 per line")
    p.add_argument("--thresholds", type=float, nargs=2, metavar=("SUSP", "MAL"), default=(0.35, 0.75))
    p.add_argument("--no-vector", action="store_true", help="omit raw vector from output records")
    p.add_argument("--log-level", default="INFO")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                        stream=sys.stderr)
    blocklist = set()
    if args.ja3_blocklist:
        with open(args.ja3_blocklist) as fh:
            blocklist = {l.split("#")[0].strip() for l in fh if l.split("#")[0].strip()}

    extractor = FeatureExtractor(normalize=not args.no_normalize,
                                 ja3_mode=args.ja3_mode, ja3_dim=args.ja3_dim)
    scorer = ThreatScorer(args.model, extractor=extractor,
                          thresholds=tuple(args.thresholds), ja3_blocklist=blocklist)
    dissector = Dissector(engine=args.engine, zeek_bin=args.zeek_bin,
                          openssl_bin=args.openssl_bin, ca_file=args.ca_file,
                          workdir=args.workdir, keep_artifacts=args.keep_artifacts)
    log.info("Engine: %s | Scorer: %s | Features: %d",
             dissector.engine_name, scorer.scorer_name, len(extractor.feature_names))

    sink = Sink(args.output)
    dump = PacketDumper(args.dump_pcap) if args.dump_pcap else None
    pipeline = Pipeline(dissector, extractor, scorer, sink, include_vector=not args.no_vector)
    try:
        if args.pcap:
            run_offline(args, pipeline, dump)
        else:
            run_live(args, pipeline, dump)
    except PermissionError:
        log.error("Permission denied - live capture needs root or CAP_NET_RAW. "
                  "With a venv, run: sudo %s app.py ...  (plain `sudo python` uses the "
                  "system interpreter, not your venv)", sys.executable)
        return 2
    except (ValueError, OSError) as e:
        if args.pcap:
            raise
        try:
            from scapy.all import get_if_list  # type: ignore
            ifaces = ", ".join(get_if_list())
        except Exception:
            ifaces = "?"
        log.error("Live capture on '%s' failed: %s | available interfaces: %s",
                  args.interface, e, ifaces)
        return 2
    finally:
        sink.close()
        if dump:
            dump.close()
    log.info("Done: %d flows | %s", pipeline.flows_done,
             ", ".join(f"{k}={v}" for k, v in sorted(sink.counts.items())) or "no flows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
