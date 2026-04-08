"""
═══════════════════════════════════════════════════════════════
  Port Sentinel  —  TCP port scanner with banner grabbing
                   and NVD CVE lookup
═══════════════════════════════════════════════════════════════
  Usage:
      python port_sentinel.py <target> [options]

  Examples:
      python port_sentinel.py 192.168.1.1
      python port_sentinel.py scanme.nmap.org -p 22,80,443
      python port_sentinel.py 10.0.0.1 -p 1-1024 --cve --min-severity HIGH
      python port_sentinel.py 10.0.0.1 --workers 200 --timeout 1.0 -o results.txt

  Features:
      • Multithreaded scanning via ThreadPoolExecutor
      • Banner grabbing with TLS/SSL fallback
      • Generic banner parser (no hardcoded product list)
      • NVD CVE lookup per open port
      • Graceful Ctrl+C shutdown with scan summary
      • Cloudflare / CDN detection

  Legal:
      Only scan targets you own or have explicit written
      permission to scan. Unauthorised scanning is illegal.
═══════════════════════════════════════════════════════════════
"""
import os
import re
import sys
import ssl
import time
import socket
import signal
import requests
import pyfiglet
import argparse
import threading
from IPy import IP
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ───────────────────────────────────────────────────────────────
#  CONFIGURATION  (defaults — all overridable via CLI flags)
# ───────────────────────────────────────────────────────────────

DEFAULT_WORKERS      = min(100, os.cpu_count() * 5)
DEFAULT_TIMEOUT      = 0.5          # seconds per connection attempt
DEFAULT_PORTS        = "1-1024"
DEFAULT_MIN_SEVERITY = "MEDIUM"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = ""            # optional — raises rate limit from 5 → 50 req/30s
                        # get a free key: nvd.nist.gov/developers/request-an-api-key

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "UNKNOWN":  0,
}

# Cloudflare's well-known alternate port fingerprint
CLOUDFLARE_PORTS = {2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096}

# Probes sent before reading a banner.
PORT_PROBES: dict[int, bytes | None] = {
    80:   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    21:   None,
    22:   None,
    25:   None,
    110:  None,
    143:  None,
    3306: None,
}

TLS_PORTS = {443, 8443, 465, 993, 995}

# Global kill-switch
stop_event = threading.Event()


# ───────────────────────────────────────────────────────────────
#  CLI ARGUMENT PARSING
# ───────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_sentinel",
        description="TCP port scanner with banner grabbing and optional NVD CVE lookup.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s 192.168.1.1\n"
            "  %(prog)s scanme.nmap.org -p 22,80,443\n"
            "  %(prog)s 10.0.0.1 -p 1-1024 --cve --min-severity HIGH\n"
            "  %(prog)s 10.0.0.1 --workers 200 --timeout 1.0 -o results.txt\n"
        ),
    )

    # ── Required ──────────────────────────────────────────────
    parser.add_argument(
        "target",
        help="Target IP address or hostname to scan.",
    )

    # ── Port selection ────────────────────────────────────────
    parser.add_argument(
        "-p", "--ports",
        default=DEFAULT_PORTS,
        metavar="PORTS",
        help=(
            "Ports to scan. Accepts individual ports, ranges, or a mix.\n"
            "Examples: 80  |  22,80,443  |  1-1024  |  1-1024,8080,9000\n"
            f"Default: {DEFAULT_PORTS}"
        ),
    )

    # ── CVE lookup ────────────────────────────────────────────
    parser.add_argument(
        "--cve",
        action="store_true",
        default=False,
        help="Enable NVD CVE lookup for each open port's banner. Off by default.",
    )

    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=DEFAULT_MIN_SEVERITY,
        metavar="LEVEL",
        help=(
            "Minimum CVE severity to display. Choices: CRITICAL, HIGH, MEDIUM, LOW.\n"
            f"Default: {DEFAULT_MIN_SEVERITY}"
        ),
    )

    # ── Performance ───────────────────────────────────────────
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=(
            f"Number of concurrent threads (1–500). Default: {DEFAULT_WORKERS}.\n"
            "Higher values are faster but may trigger firewalls or exhaust file descriptors."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECS",
        help=(
            f"Per-connection timeout in seconds (0.1–10.0). Default: {DEFAULT_TIMEOUT}.\n"
            "Increase for slow or high-latency targets."
        ),
    )

    # ── Output ────────────────────────────────────────────────
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="Save scan results to a text file (appends if the file exists).",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show closed/filtered ports in addition to open ones.",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """
    Cross-field validation that argparse can't express declaratively.
    Exits with a clear message on any invalid combination.
    """
    if not (1 <= args.workers <= 500):
        _exit_error(f"--workers must be between 1 and 500 (got {args.workers})")

    if not (0.1 <= args.timeout <= 10.0):
        _exit_error(f"--timeout must be between 0.1 and 10.0 (got {args.timeout})")


def _exit_error(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)
    sys.exit(2)


# ───────────────────────────────────────────────────────────────
#  PORT STRING PARSER
# ───────────────────────────────────────────────────────────────

def parse_ports(port_str: str) -> list[int]:
    """
    Parse a port specification string into a sorted list of port numbers.

    Accepts:
        "80"               → [80]
        "22,80,443"        → [22, 80, 443]
        "1-1024"           → [1, 2, …, 1024]
        "1-1024,8080,9000" → [1, 2, …, 1024, 8080, 9000]
    """
    ports = set()
    try:
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
                if not (1 <= start <= end <= 65535):
                    raise ValueError(f"Invalid range: {part}")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
    except ValueError as exc:
        _exit_error(f"Invalid --ports value '{port_str}': {exc}")

    return sorted(ports)


# ───────────────────────────────────────────────────────────────
#  DISPLAY BANNER
# ───────────────────────────────────────────────────────────────

def print_banner() -> None:
    print(pyfiglet.figlet_format("Port-Sentinel", font="slant"))


# ───────────────────────────────────────────────────────────────
#  RESOLVE HOSTNAME → IPv4
# ───────────────────────────────────────────────────────────────

def resolve_hostname(target: str) -> str:
    try:
        IP(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


# ───────────────────────────────────────────────────────────────
#  PRINT SCAN HEADER
# ───────────────────────────────────────────────────────────────

def print_scan_header(target_ip: str, args: argparse.Namespace, ports: list[int]) -> None:
    lines = [
        "-" * 60,
        f"  Target      : {target_ip}",
        f"  Ports       : {args.ports}  ({len(ports)} total)",
        f"  Workers     : {args.workers}",
        f"  Timeout     : {args.timeout}s",
        f"  CVE lookup  : {'yes — min severity: ' + args.min_severity if args.cve else 'no'}",
        f"  Output file : {args.output or 'none'}",
        f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 60,
    ]
    for line in lines:
        print(line)


# ───────────────────────────────────────────────────────────────
#  BANNER GRABBING
# ───────────────────────────────────────────────────────────────

def grab_banner(sock: socket.socket, port: int) -> str | None:
    try:
        probe = PORT_PROBES.get(port)

        if port in TLS_PORTS:
            try:
                context                = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode    = ssl.CERT_NONE
                tls_sock = context.wrap_socket(sock, server_hostname="localhost")
                if probe:
                    tls_sock.sendall(probe)
                tls_sock.settimeout(1.0)
                raw = tls_sock.recv(1024).decode(errors="ignore").strip()
                return raw.splitlines()[0] if raw else None
            except ssl.SSLError:
                pass

        if probe:
            sock.sendall(probe)

        sock.settimeout(1.0)
        raw = sock.recv(1024).decode(errors="ignore").strip()
        return raw.splitlines()[0] if raw else None

    except Exception:
        return None


# ───────────────────────────────────────────────────────────────
#  SINGLE PORT PROBE
# ───────────────────────────────────────────────────────────────

def probe_port(
    target_ip: str,
    target_port: int,
    timeout: float,
) -> tuple[bool, str | None]:
    """
    Attempt a full TCP connect to target_ip:target_port.
    `timeout` is now passed in from args rather than hardcoded.
    """
    if stop_event.is_set():
        return False, None

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, target_port))
        banner = grab_banner(sock, target_port)
        return True, banner
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False, None
    finally:
        if sock:
            sock.close()


# ───────────────────────────────────────────────────────────────
#  BANNER PARSING
# ───────────────────────────────────────────────────────────────

def parse_banner(banner: str) -> tuple[str | None, str | None]:
    if not banner:
        return None, None

    match = re.search(
        r"([A-Za-z][\w\-]{1,30})"
        r"[/\s_\-]"
        r"v?([\d]+\.[\d][\w.]*)",
        banner,
    )
    if match:
        return match.group(1).lower(), match.group(2)

    match = re.search(
        r"([A-Za-z][\w]{2,20})"
        r"\s+"
        r"v?([\d]+\.[\d][\w.]*)",
        banner,
        re.IGNORECASE,
    )
    if match:
        return match.group(1).lower(), match.group(2)

    return None, None


# ───────────────────────────────────────────────────────────────
#  NVD CVE LOOKUP
# ───────────────────────────────────────────────────────────────

def _query_nvd(params: dict) -> list[dict]:
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    try:
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=5)
        resp.raise_for_status()
        results = []
        for item in resp.json().get("vulnerabilities", []):
            cve      = item["cve"]
            desc     = cve["descriptions"][0]["value"]
            severity = (
                cve.get("metrics", {})
                   .get("cvssMetricV31", [{}])[0]
                   .get("cvssData", {})
                   .get("baseSeverity", "UNKNOWN")
            )
            results.append({
                "id":          cve["id"],
                "severity":    severity,
                "description": desc[:120],
            })
        return results
    except Exception:
        return []


def _filter_by_severity(cves: list[dict], min_severity: str) -> list[dict]:
    threshold = SEVERITY_RANK.get(min_severity, 0)
    return [c for c in cves if SEVERITY_RANK.get(c["severity"], 0) >= threshold]


def lookup_cves(banner: str, min_severity: str) -> list[dict]:
    time.sleep(0.6)
    product, version = parse_banner(banner)
    keyword = f"{product} {version}" if (product and version) else banner.splitlines()[0][:100].strip()
    if not keyword:
        return []
    cves = _query_nvd({"keywordSearch": keyword, "resultsPerPage": 5})
    return _filter_by_severity(cves, min_severity)


# ───────────────────────────────────────────────────────────────
#  CLOUDFLARE / CDN DETECTION
# ───────────────────────────────────────────────────────────────

def detect_cloudflare(open_ports: list[int]) -> bool:
    return len(CLOUDFLARE_PORTS.intersection(set(open_ports))) >= 3


# ───────────────────────────────────────────────────────────────
#  SIGNAL HANDLER  (Ctrl+C)
# ───────────────────────────────────────────────────────────────

def handle_sigint(signum, frame) -> None:
    print("\n\n[!] Ctrl+C detected — stopping scan gracefully ...")
    stop_event.set()


# ───────────────────────────────────────────────────────────────
#  SCAN PORTS
# ───────────────────────────────────────────────────────────────

def scan_ports(target_ip: str, args: argparse.Namespace, ports: list[int]) -> None:
    """
    Scan the given list of ports using settings from `args`.
    All hardcoded values replaced by args.workers, args.timeout, etc.
    """
    print(f"\n[# Scanning Target]: {target_ip}\n")

    open_ports: list[int] = []
    output_lines: list[str] = []
    scanned = 0
    total   = len(ports)

    def emit(line: str) -> None:
        """Print a line and optionally buffer it for file output."""
        print(line)
        if args.output:
            output_lines.append(line)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:

        futures: dict = {
            executor.submit(probe_port, target_ip, port, args.timeout): port
            for port in ports
        }

        try:
            for future in as_completed(futures):

                if stop_event.is_set():
                    for pending in futures:
                        pending.cancel()
                    break

                scanned += 1
                port = futures[future]

                try:
                    is_open, banner = future.result()
                except Exception:
                    continue

                if not is_open:
                    if args.verbose:
                        print(f"  [----]  Port {port:<6} — closed/filtered")
                    continue

                # ── Port is open ───────────────────────────────
                open_ports.append(port)

                if banner:
                    emit(f"  [OPEN]  Port {port:<6} — {banner[:80]}")

                    if args.cve:
                        cves = lookup_cves(banner, args.min_severity)
                        if cves:
                            for cve in cves:
                                line = (
                                    f"    ⚠   {cve['id']:<18} "
                                    f"[{cve['severity']}]{'':5} "
                                    f"{cve['description']}"
                                )
                                emit(line)
                        else:
                            product, version = parse_banner(banner)
                            if product and version:
                                emit(
                                    f"    ✓   No {args.min_severity}+ CVEs found "
                                    f"for {product} {version}"
                                )
                else:
                    emit(f"  [OPEN]  Port {port:<6} — (no banner)")

        finally:
            summary = [
                "",
                "=" * 60,
            ]

            if stop_event.is_set():
                summary.append(
                    f"  [!] Scan interrupted — {scanned:,} / {total:,} ports checked."
                )
            else:
                summary.append(
                    f"  Scan finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )

            summary += [
                f"  Open ports    : {len(open_ports)}",
            ]

            if open_ports:
                summary.append(f"  Ports         : {', '.join(str(p) for p in sorted(open_ports))}")

            if detect_cloudflare(open_ports):
                summary += [
                    "",
                    "  ⚠  Cloudflare detected — target is behind a CDN.",
                    "     The real origin server is hidden.",
                    "     Results reflect the edge node only.",
                ]

            summary.append("=" * 60 + "\n")

            for line in summary:
                emit(line)

            # ── Write output file ──────────────────────────────
            if args.output and output_lines:
                try:
                    with open(args.output, "a", encoding="utf-8") as f:
                        f.write(f"\n# Scan of {target_ip} — {datetime.now().isoformat()}\n")
                        f.write("\n".join(output_lines) + "\n")
                    print(f"  Results saved to: {args.output}")
                except OSError as exc:
                    print(f"  [!] Could not write output file: {exc}", file=sys.stderr)


# ───────────────────────────────────────────────────────────────
#  MAIN
# ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Cross-field validation
    validate_args(args)

    # ASCII art title
    print_banner()

    # Resolve hostname
    try:
        target_ip = resolve_hostname(args.target)
    except socket.gaierror:
        _exit_error(f"Could not resolve hostname: {args.target}")

    # Parse port list
    ports = parse_ports(args.ports)

    # Register Ctrl+C handler BEFORE scan starts
    signal.signal(signal.SIGINT, handle_sigint)

    # Scan header
    print_scan_header(target_ip, args, ports)

    # Run the scan
    try:
        scan_ports(target_ip, args, ports)
    except socket.error as exc:
        print(f"\n[!] Socket error — server may not be responding: {exc}")
        sys.exit(1)

    sys.exit(0 if not stop_event.is_set() else 1)


if __name__ == "__main__":
    main()