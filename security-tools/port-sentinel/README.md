# Port Sentinel 🔍

A fast, multithreaded TCP port scanner built from scratch in Python — featuring banner grabbing,
TLS/SSL detection, NVD CVE lookup, graceful Ctrl+C shutdown, and Cloudflare CDN detection.

> Built as a learning project to understand how tools like Nmap work at the socket level.

---

## Features

| Feature | Detail |
|---|---|
| Multithreaded scanning | `ThreadPoolExecutor` — full 65,535 port scan in ~2 minutes |
| Banner grabbing | Automatic TLS/SSL upgrade for HTTPS ports |
| Generic banner parser | Extracts product + version from any service — no hardcoded list |
| NVD CVE lookup | Queries the National Vulnerability Database per open port (optional flag) |
| Severity filtering | Show only CRITICAL / HIGH / MEDIUM / LOW CVEs |
| Graceful shutdown | Clean Ctrl+C exit via `threading.Event` + `SIGINT` handler |
| Cloudflare detection | Warns when the target is behind a CDN / reverse proxy |
| Flexible port selection | Single ports, ranges, or mixed: `22,80,1-1024` |
| Output to file | Save full results with `-o results.txt` |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/<your-username>/port-sentinel.git
cd port-sentinel
pip install -r requirements.txt
```

**`requirements.txt`**
```
requests
pyfiglet
IPy
```

---

## Usage

```bash
python port_sentinel.py <target> [options]
```

### Quick Examples

```bash
# Scan default ports (1–1024)
python port_sentinel.py scanme.nmap.org

# Scan specific ports
python port_sentinel.py 192.168.1.1 -p 22,80,443

# Scan a range with CVE lookup, HIGH+ severity only
python port_sentinel.py 10.0.0.1 -p 1-1024 --cve --min-severity HIGH

# Full scan with custom workers, timeout, and file output
python port_sentinel.py 10.0.0.1 -p 1-65535 --workers 300 --timeout 1.0 -o results.txt
```

### All Flags

| Flag | Default | Description |
|---|---|---|
| `target` | required | IP address or hostname to scan |
| `-p, --ports` | `1-1024` | Port spec: `80` · `22,80,443` · `1-1024` · `1-1024,8080` |
| `--cve` | off | Enable NVD CVE lookup for each open port |
| `--min-severity` | `MEDIUM` | CVE threshold: `CRITICAL` `HIGH` `MEDIUM` `LOW` |
| `--workers` | auto | Concurrent threads (1–500) |
| `--timeout` | `0.5` | Per-connection timeout in seconds (0.1–10.0) |
| `-o, --output` | none | Save results to a text file (appends if file exists) |
| `-v, --verbose` | off | Also show closed / filtered ports |

---

## Sample Output

```
  [OPEN]  Port 21     — 220 vsftpd 2.3.4
    ⚠   CVE-2011-2523       [CRITICAL]    vsftpd 2.3.4 contains a backdoor introduced
                                          into the source code that allows remote...
  [OPEN]  Port 22     — SSH-2.0-OpenSSH_7.2p2
    ⚠   CVE-2016-6210       [MEDIUM]      OpenSSH through 7.2p2 allows remote attackers
                                          to enumerate valid usernames via timing...
  [OPEN]  Port 80     — HTTP/1.1 403 Forbidden
    ✓   No MEDIUM+ CVEs found for http 1.1
  [OPEN]  Port 443    — (no banner)

============================================================
  Scan finished : 2026-04-07 21:45:03
  Open ports    : 4
  Ports         : 21, 22, 80, 443
============================================================
```

---

## How It Works

### Architecture

```
main()
  ├── build_parser()          parse CLI flags
  ├── validate_args()         cross-field validation
  ├── resolve_hostname()      DNS → IPv4  (IPy for validation)
  ├── signal.signal(SIGINT)   register Ctrl+C handler before scan
  └── scan_ports()
        ├── ThreadPoolExecutor(max_workers)
        │     └── probe_port()        TCP connect + grab_banner()
        │           └── grab_banner() TLS upgrade or plain recv
        ├── parse_banner()    generic regex — no hardcoded product names
        ├── lookup_cves()     NVD keyword search → severity filter
        └── detect_cloudflare() port fingerprint heuristic
```

### Threading Model

Ports are submitted as futures to a `ThreadPoolExecutor`. Results are consumed
via `as_completed()` so open ports print immediately rather than waiting for the
full scan to finish. A global `threading.Event` (`stop_event`) acts as a kill-switch
— every worker checks it before opening a socket, so Ctrl+C drains the pool cleanly
without a traceback.

```
Sequential scan:  Port 1 → wait → Port 2 → wait → ...  (~9 hrs for 65 535 ports)
Threaded scan:    300 ports probed simultaneously        (~2 min for 65 535 ports)
```

### Banner Grabbing

```
connect()
   │
   ├── Port in TLS_PORTS?  →  ssl.wrap_socket()  →  send probe  →  recv
   │
   └── Plain port          →  send probe (if needed)  →  recv
                                  │
                                  └── None probe = service speaks first
                                      (FTP, SSH, SMTP, MySQL…)
```

### CVE Lookup Pipeline

```
banner
  │
  ├── parse_banner()  →  product + version found
  │       │                    │
  │       │           keyword = "nginx 1.18.0"
  │       │
  │       └── no version found
  │                    │
  │           keyword = raw banner (first 100 chars)
  │
  └── _query_nvd(keywordSearch=keyword)
          │
          └── _filter_by_severity()  →  drop below MIN_SEVERITY  →  print
```

### Cloudflare Detection

Cloudflare edge nodes consistently expose a specific set of alternate ports
(`2052 2053 2082 2083 2086 2087 2095 2096`). When 3 or more of these are found
open, the scanner warns that the target is behind a CDN and results reflect the
edge node, not the origin server.

---

## CVE Lookup Setup (Optional)

CVE lookup uses the [NVD REST API v2.0](https://nvd.nist.gov/developers/vulnerabilities) — free, no account required for basic use.

| | Rate limit |
|---|---|
| Without API key | 5 requests / 30 seconds |
| With free API key | 50 requests / 30 seconds |

To add your key, set `NVD_KEY` near the top of `port_sentinel.py`:

```python
NVD_KEY = "your-key-here"
```

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

---

## Why I Built This

I wanted to understand how port scanners like Nmap work at the socket level rather
than just using them as black boxes. Building this from scratch surfaced a number of
real engineering problems:

- **OS thread limits** — Python crashed at ~1,500 threads when creating one per port.
  Switching to `ThreadPoolExecutor` with a bounded worker count fixed this.
- **SIGINT propagation** — `KeyboardInterrupt` doesn't bubble cleanly through
  `concurrent.futures`. A `threading.Event` + `signal.signal(SIGINT, ...)` handler
  solved the graceful shutdown problem.
- **Banner parsing at scale** — Hardcoding one regex per product doesn't scale to
  250,000+ CVEs. Two generic patterns cover the vast majority of real-world banners
  without any product-specific knowledge.
- **Cloudflare interference** — Scanning `webgoat.org` returned 13 open ports, none
  of which belonged to WebGoat. Recognising the Cloudflare port fingerprint
  (`2052 2053 2082 2083 2086 2087 2095 2096`) explains the result immediately.

---

## Comparison with Nmap

| | Port Sentinel | Nmap |
|---|---|---|
| Language | Python | C |
| I/O model | `ThreadPoolExecutor` | Async epoll/kqueue |
| TCP method | Full connect (`-sT` equivalent) | SYN half-open (`-sS`) by default |
| Timeout | Configurable, per-connection | Dynamic RTT-based |
| Root required | No | For SYN scan |
| Speed (65 535 ports) | ~2 min @ 300 workers | ~5 s (`-sS`) / ~20 s (`-sT`) |
| CVE lookup | Built-in (NVD API) | Via NSE scripts |
| CDN detection | Built-in heuristic | Via NSE scripts |

Port Sentinel matches Nmap's `-sT` (full connect) mode in method. The speed gap
comes from Nmap's C implementation and raw-socket SYN scanning, which requires root
and never completes the TCP handshake — making it ~3× faster per port.

---

## Tested Against

| Target | Notes |
|---|---|
| `scanme.nmap.org` | Nmap's official sanctioned test host |
| Metasploitable 2 | Intentionally vulnerable VM — rich open port set |
| DVWA (Docker) | Web app vulnerability testing |
| `webgoat.org` | Revealed Cloudflare CDN — led to CDN detection feature |

---

## Roadmap

- [ ] Subnet scanning (`--range 192.168.1.0/24`)
- [ ] JSON report export (`--format json`)
- [ ] OS fingerprinting via TTL analysis
- [ ] Go rewrite for raw-socket SYN scanning

---

## Legal

This tool is for **authorised security testing only**.

Only scan systems you own or have **explicit written permission** to test.
Unauthorised port scanning may be illegal under computer fraud laws in your
jurisdiction (CFAA in the US, Computer Misuse Act in the UK, and equivalents elsewhere).

The author assumes no liability for misuse of this tool.

---

## Tech Stack

`Python 3.10+` · `concurrent.futures` · `socket` · `ssl` · `signal` · `threading` · `requests` · `pyfiglet` · `IPy` · `argparse`

---

## License

MIT — see [LICENSE](LICENSE) for details.
