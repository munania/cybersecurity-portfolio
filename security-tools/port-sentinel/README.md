# Port Sentinel 🔍

A fast, multithreaded TCP port scanner with banner grabbing, TLS detection,
NVD CVE lookup, and graceful shutdown — built from scratch in Python.

---

## Features

- **Multithreaded scanning** via `ThreadPoolExecutor` — full 65,535 port scan in ~2 minutes
- **Banner grabbing** with automatic TLS/SSL fallback for HTTPS ports
- **Generic banner parser** — extracts product + version from any service without a hardcoded list
- **NVD CVE lookup** — queries the National Vulnerability Database per open port (optional)
- **Severity filtering** — show only CRITICAL, HIGH, MEDIUM, or LOW CVEs
- **Graceful Ctrl+C shutdown** — clean exit with partial results via `threading.Event` + `SIGINT`
- **Cloudflare / CDN detection** — warns when the target is behind a reverse proxy
- **Flexible port selection** — single ports, ranges, or mixed (`22,80,1-1024`)
- **Output to file** — save results with `-o results.txt`

---

## Installation

```bash
git clone https://github.com/<your-username>/port-sentinel.git
cd port-sentinel
pip install -r requirements.txt
```

---

## Usage

```bash
python port_sentinel.py <target> [options]
```

### Examples

```bash
# Scan default ports (1–1024)
python port_sentinel.py scanme.nmap.org

# Scan specific ports
python port_sentinel.py 192.168.1.1 -p 22,80,443

# Scan a range with CVE lookup, show only HIGH+ CVEs
python port_sentinel.py 10.0.0.1 -p 1-1024 --cve --min-severity HIGH

# Full scan with custom workers, timeout, and file output
python port_sentinel.py 10.0.0.1 -p 1-65535 --workers 300 --timeout 1.0 -o results.txt
```

### All Options

| Flag | Default | Description |
|------|---------|-------------|
| `target` | required | IP address or hostname |
| `-p, --ports` | `1-1024` | Ports: `80`, `22,80,443`, `1-1024`, `1-1024,8080` |
| `--cve` | off | Enable NVD CVE lookup per open port |
| `--min-severity` | `MEDIUM` | CVE threshold: `CRITICAL` `HIGH` `MEDIUM` `LOW` |
| `--workers` | auto | Concurrent threads (1–500) |
| `--timeout` | `0.5` | Per-connection timeout in seconds |
| `-o, --output` | none | Save results to file |
| `-v, --verbose` | off | Show closed/filtered ports too |

---

## Sample Output