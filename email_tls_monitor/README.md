# Email TLS Security Monitor

Passive monitor for SMTP / IMAP / POP3 traffic. It captures packets live or reads a pcap, rebuilds each TCP session, and dissects it with **Zeek** and **OpenSSL**. Each session becomes a `np.float32` feature vector, which an ML model scores. If you don't supply a model, a transparent heuristic scores it instead.

```
capture.py ──flows──▶ dissector.py ──FlowAnalysis──▶ features.py ──vector──▶ model.py ──▶ JSONL
 (Scapy)              Zeek + OpenSSL + native TLS     entropy / JA3 / NumPy   ThreatScorer
```

## System dependencies

| Tool | Why | Install (Debian/Ubuntu) |
|---|---|---|
| `zeek` ≥ 5.0 | Modules A/B (conn, smtp, files, ssl, x509 logs) | [Zeek packages](https://docs.zeek.org/en/current/install.html) (OBS repo) |
| `zkg install ja3` | Module D: `ja3` / `ja3s` columns in ssl.log | `zkg autoconfig && zkg install ja3` |
| `openssl` | Module C: `openssl x509 -text -noout`, `openssl verify` | `apt install openssl` |
| `libpcap` | Kernel BPF filtering for live capture | `apt install libpcap0.8` |

```bash
pip install -r requirements.txt
```

**Windows:** Zeek has no native Windows build, so run the monitor under WSL2 or a Linux VM. If you stay on Windows, use `--engine native` with Npcap installed. Every feature below still works except the Zeek-only log fields.

## Usage

```bash
# Offline: JSON Lines output, one record per flow
python app.py --pcap capture.pcapng --output ratings.jsonl

# Live, with a trained model, also saving the email packets
sudo .venv/bin/python app.py --interface eth0 --model model.joblib --output live.jsonl --dump-pcap email.pcap

# Demo pcap: 5 flows covering cleartext auth, a self-signed cert, TLS 1.3, STARTTLS, and a timeout
python samples/generate_sample_pcap.py demo.pcap certs/
python app.py --pcap demo.pcap --ca-file certs/test-ca.pem --output demo.json
python -m pytest -q tests/
```

## Web dashboard (demo UI)

```bash
python dashboard.py            # open http://127.0.0.1:8080 and click "Demo replay"
sudo .venv/bin/python dashboard.py --interface wlan0   # live capture from the UI too
```

Standard library only (no Flask, no CDN), so it works offline. It runs the same pipeline and streams every scored flow to the browser: a live flow feed, KPIs, the verdict mix, risk per flow, top threat signals and TLS posture. Click any flow to see its noisy-OR evidence, TLS handshake, certificate, email metadata and the 20-d feature vector. Sources are **Demo replay** (the bundled sample capture, analysed for real and then replayed), **Upload PCAP** and **Live capture**. Use `-o flows.jsonl` to also log to a file.

Key flags: `--engine auto|zeek|native`, `--timeout 4` (idle expiry, seconds), `--batch-size`, `--batch-interval`, `--ja3-mode scalar|embedding`, `--ja3-blocklist file`, `--thresholds 0.35 0.75`, `--keep-artifacts`, `--ca-file`.

## How it works

**Capture.** The BPF filter covers ports 25, 465, 587, 143, 993, 110 and 995. Packets are grouped into bidirectional 5-tuple flows. A flow is emitted when it ends with an RST, when both sides have sent a FIN, when it has been idle for `--timeout` seconds, or at end of input. Trailing ACKs after a close are ignored.

**Dissection.** Flows are sent to Zeek in batches: one pcap and one `zeek` run per batch. The generated script loads:
- `extract-all-files`
- `validate-certs`
- a custom `email_cmds.log` of cleartext SMTP/POP3 verbs plus IMAP STARTTLS
- a `handshake_duration` column in ssl.log (ClientHello → `ssl_established`)
- the JA3 package, if `zkg` installed it

Leaf certificates are matched in two ways. The ssl.log `cert_chain_fps[0]` (SHA-256) is compared against hashes of the extracted files. On older Zeek versions, the `cert_chain_fuids` value is matched against the extracted file names instead. The matched certificate is then parsed with `openssl x509 -text -noout -nameopt RFC2253`.

A built-in **native** dissector also runs on every flow. It does TCP reassembly, then parses ClientHello, ServerHello and Certificate messages, computes JA3/JA3S (with GREASE values stripped), parses MIME, and runs `openssl verify -attime <capture time>`. It fills in any field Zeek left empty, and it is the only engine used when Zeek is missing.

**Features** (`features.BASE_FEATURES`, 20 dims): the 15 you asked for, followed by `tls_version`, `tls_observed`, `cert_observed`, `cleartext_auth`, `starttls`. Missing values are `-1.0`. Duration, byte counts and lifespan are `log1p`-scaled unless you pass `--no-normalize`. JA3 is encoded as a stable hash scalar in [0,1) by default. `--ja3-mode embedding` switches to k-dimensional signed feature hashing, which is better for linear models and neural nets.

**Scoring.** `ThreatScorer` loads a `.joblib` or `.onnx` model. For the heuristic fallback, each indicator has a weight and they are combined as a noisy-OR: `P = 1 − ∏(1 − wᵢ)`. The heuristic indicators are reported even when an ML model makes the call, so every rating comes with evidence.

## Training your own model

```python
import joblib, json
from features import FeatureExtractor
fx = FeatureExtractor()
# X: vectors from the "vector" field of the JSONL output, y: your labels (0 benign / 1 malicious)
clf = ...fit(X, y)
joblib.dump({"model": clf, "feature_names": fx.feature_names, "thresholds": (0.35, 0.75)}, "model.joblib")
```

When a model is saved as a bundle with `feature_names`, loading it with a different feature layout fails loudly instead of silently producing wrong scores. Tree ensembles such as RandomForest, HistGradientBoosting and XGBoost suit the scalar JA3 encoding.

## Known limits

- **TLS 1.3 encrypts the server certificate.** Certificate features are `-1` for TLS 1.3 flows, and `cert_observed=0` marks that.
- **Encrypted content is invisible.** After STARTTLS, and on ports 465/993/995, commands, subjects and attachments are all encrypted. Content features only apply to cleartext sessions.
- **Zeek has no IMAP command log.** Zeek's IMAP analyzer only reports STARTTLS. The native engine parses IMAP verbs from cleartext sessions.
- **Long-lived sessions get split.** With a 3–5 s idle timeout, IMAP IDLE and slow SMTP sessions are cut into several "flows". Raise `--timeout` (e.g. 60) for production.
- **Short-lived certificates are becoming normal.** The CA/B Forum is phasing in shorter maximum lifetimes: 200 days from March 2026, falling to 47 days by 2029. Let's Encrypt also issues 6-day certs. The `ephemeral_cert_lifespan` weight is therefore deliberately modest, and `excessive_cert_lifespan` (> 398 days) is the stronger signal.
- **Extracted files contain real attachments.** `extract-all-files` writes attachments, possibly malware, into the batch directory. The directory is deleted after each batch unless you pass `--keep-artifacts`. Endpoint AV may still react to it.
- **CA trust for the native engine.** Its `openssl verify` uses OpenSSL's default CA store. Pass `--ca-file` if your OpenSSL build has none, which is common on Windows. Otherwise every certificate fails validation.
