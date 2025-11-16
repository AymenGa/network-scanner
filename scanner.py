#!/usr/bin/env python3


from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import argparse
import time
import json
from typing import List, Tuple, Optional, Dict

from colorama import init as colorama_init, Fore, Style
from tqdm import tqdm
import string

# Init colorama
colorama_init(autoreset=True)

# Defaults / presets
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 0.4
DEFAULT_BANNER = 256
PRESETS = {
    'fast': '1-1024',
    'common': '1-1024,3306,8080',
    'full': '1-65535'
}

# Noisy Windows/local ports to optionally hide
NOISY_PORTS = {
    17500,  # Dropbox LAN
    6463,   # Discord RPC local
    7680,   # Windows Delivery Optimization
    7768,   # Desktop API tunnel
    49664, 49665, 49666, 49667, 49668,
    49669, 49670, 49671, 49672, 49673
}

# Severity ordering
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

# ---------- Helper functions ----------

def parse_ports(spec: str) -> List[int]:
    spec = spec.strip()
    if spec in PRESETS:
        spec = PRESETS[spec]
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                a = int(a); b = int(b)
                if a > b:
                    a, b = b, a
                ports.update(range(max(1, a), min(65535, b) + 1))
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                continue
    return sorted(ports)

def resolve_target(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        raise RuntimeError(f"Could not resolve target '{host}': {e}")

def try_get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, 'tcp')
    except Exception:
        return ""

def sanitize_banner(raw: str, max_len: int = 200) -> str:
    """Make a banner printable and reasonably short for CLI display."""
    if not raw:
        return ""
    # Replace non-printable chars with a space
    printable = ''.join(ch if ch in string.printable else ' ' for ch in raw)
    # Collapse multiple whitespace
    printable = ' '.join(printable.split())
    if len(printable) > max_len:
        return printable[:max_len-3] + '...'
    return printable

def attempt_banner(sock: socket.socket, max_bytes: int, default_timeout: float) -> str:
    try:
        sock.settimeout(min(0.25, sock.gettimeout() or default_timeout))
        try:
            sock.sendall(b"\r\n")
        except Exception:
            pass
        data = sock.recv(max_bytes)
        if not data:
            return ""
        try:
            return data.decode(errors='ignore').strip()
        except Exception:
            return ""
    except Exception:
        return ""

def scan_port_once(ip: str, port: int, timeout: float, banner_size: int) -> Optional[Tuple[int, str]]:
    """Attempt a TCP connect; return (port, banner_or_service) if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = attempt_banner(s, banner_size, timeout)
            service = try_get_service(port) or ""
            info = banner or service or "open"
            return (port, info)
    except Exception:
        return None

# ---------- Security assessment (improved) ----------

def assess_security(port: int, banner: str) -> Dict[str, str]:
    """
    Return a dict: {"severity": "low|medium|high|info", "note": "..."}
    Precise, actionable client-friendly guidance based on port and banner.
    """
    # direct port-based rules (concise and practical)
    PORT_RULES = {
        21:  ("medium", "FTP (cleartext) — avoid exposing; prefer SFTP/FTPS."),
        22:  ("low",    "SSH — keep key-based auth, disable weak ciphers and passwords."),
        23:  ("high",   "Telnet — insecure; replace with SSH."),
        25:  ("high",   "SMTP — check relay config if public."),
        53:  ("high",   "DNS open resolver risk — restrict to known clients."),
        80:  ("medium", "HTTP (cleartext) — redirect to HTTPS and use HSTS."),
        110: ("medium", "POP3 (cleartext) — prefer secure IMAP/POP3 or TLS."),
        139: ("high",   "NetBIOS/SMB-related — avoid exposing to internet."),
        143: ("medium", "IMAP — ensure TLS is enabled for remote clients."),
        443: ("low",    "HTTPS — check TLS config, cert validity and modern ciphers."),
        445: ("high",   "SMB — high risk if exposed externally; block if unnecessary."),
        3306:("high",   "MySQL — do not expose to internet; use network restrictions."),
        3389:("high",   "RDP — critical if exposed; use VPN, MFA, and account lockouts."),
        5432:("high",   "PostgreSQL — restrict to internal hosts."),
        5900:("medium", "VNC — weak default auth; use secure tunnels."),
        6379:("high",   "Redis default — often unauthenticated; restrict access."),
        8080:("medium", "Alternate HTTP — check for admin panels."),
        9200:("high",   "Elasticsearch — sensitive, often contains data; restrict."),
        27017:("high",  "MongoDB — older defaults allowed unauthenticated access; secure it."),
    }

    # 1) Port-specific rule
    if port in PORT_RULES:
        sev, note = PORT_RULES[port]
        return {"severity": sev, "note": note}

    # 2) Banner-based heuristics
    b = (banner or "").lower()

    # common banners -> helpful guidance
    if "ssh" in b:
        return {"severity": "low", "note": "SSH detected — enforce key-based auth and update regularly."}
    if "apache" in b or "nginx" in b or "http/" in b:
        return {"severity": "medium", "note": "Web service detected — ensure current version and HTTPS."}
    if "mysql" in b or "mariadb" in b:
        return {"severity": "high", "note": "Database detected (MySQL/MariaDB) — avoid remote exposure."}
    if "postgres" in b or "postgresql" in b:
        return {"severity": "high", "note": "Postgres detected — restrict network access and authenticate."}
    if "redis" in b:
        return {"severity": "high", "note": "Redis-like response — often unauthenticated by default; secure it."}
    if "mongodb" in b or "mongo" in b:
        return {"severity": "high", "note": "MongoDB detected — check for authentication and bind settings."}
    if "microsoft-ds" in b or "smb" in b or "netbios" in b:
        return {"severity": "high", "note": "SMB/NetBIOS-related service — avoid public exposure."}
    if any(x in b for x in ("jsonrpc", "rpc", "desktop_api")):
        return {"severity": "info", "note": "RPC/JSON-RPC or internal API detected — likely internal traffic."}
    if b.startswith("{") and ("jsonrpc" in b or "error" in b):
        # framed JSON payloads often internal
        return {"severity": "info", "note": "Framed JSON/JSON-RPC response — internal application protocol."}
    if any(c in b for c in ("http", "server:", "get ", "post ")):
        return {"severity": "medium", "note": "HTTP-like response — review site configuration and TLS."}

    # Default fallback
    return {"severity": "info", "note": "Unknown service — if exposed externally, review necessity and configuration."}

# ---------- Scanning core (with progress and optional noisy filtering) ----------

def scan_host(target: str, ports: List[int], workers: int, timeout: float, banner_size: int, no_noisy: bool) -> Tuple[List[Tuple[int, str]], float]:
    """Scan ports and return list of (port, info) and elapsed seconds."""
    target_ip = resolve_target(target)
    results: List[Tuple[int, str]] = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures_map = {exe.submit(scan_port_once, target_ip, p, timeout, banner_size): p for p in ports}
        # tqdm over as_completed; total known
        for fut in tqdm(as_completed(futures_map), total=len(futures_map), desc="Scanning", unit="port"):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                port, info = res
                if no_noisy and port in NOISY_PORTS:
                    continue
                results.append((port, info))

    elapsed = time.time() - start
    results.sort()
    return results, elapsed

# ---------- JSON payload builder (with security feedback) ----------

def build_json_payload(target: str, target_ip: str, ports_spec: str, ports_list: List[int],
                       found: List[Tuple[int, str]], elapsed: float, meta: Dict) -> Dict:
    open_ports = []
    for p, info in found:
        sec = assess_security(p, info)
        open_ports.append({
            "port": p,
            "info": info,
            "security_feedback": sec
        })
    return {
        "target": target,
        "resolved_ip": target_ip,
        "ports_requested": ports_spec,
        "ports_scanned": len(ports_list),
        "open_ports": open_ports,
        "scan_time_seconds": round(elapsed, 3),
        "meta": meta
    }

# ---------- Text report writer ----------

def write_text_report(path: str, payload: Dict):
    lines = []
    lines.append(f"Scan report for {payload['target']} ({payload['resolved_ip']})")
    lines.append(f"Ports scanned: {payload['ports_scanned']}   Time: {payload['scan_time_seconds']}s")
    lines.append("")
    lines.append("Open ports and security feedback:")
    for entry in payload["open_ports"]:
        p = entry["port"]
        info = entry["info"]
        sec = entry.get("security_feedback", {})
        sev = sec.get("severity", "info")
        note = sec.get("note", "")
        lines.append(f"- {p}: {info}")
        lines.append(f"  -> severity: {sev}    note: {note}")
        lines.append("")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"{Fore.CYAN}[i] Text report saved to {path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to write report {path}: {e}{Style.RESET_ALL}")

# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Threaded TCP scanner with security feedback (detailed table).")
    p.add_argument('-t', '--target', required=True, help='Target hostname or IPv4 address.')
    p.add_argument('-p', '--ports', default='common', help='Ports: preset (fast|common|full) or list/range (22,80,1-1024).')
    p.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, help=f'Worker threads (default {DEFAULT_WORKERS}).')
    p.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help=f'Timeout seconds (default {DEFAULT_TIMEOUT}).')
    p.add_argument('--banner-size', type=int, default=DEFAULT_BANNER, help=f'Max banner bytes (default {DEFAULT_BANNER}).')
    p.add_argument('--yes', action='store_true', help='Skip permission reminder.')
    p.add_argument('--json', action='store_true', help='Print JSON output after scan.')
    p.add_argument('-o', '--output', help='Save JSON results to a file (path).')
    p.add_argument('--no-noisy', action='store_true', help='Hide noisy Windows/local ports.')
    p.add_argument('--report', help='Save a human-readable text report to this path.')
    p.add_argument('--min-severity', choices=['info', 'low', 'medium', 'high'], default='info', help='Minimum severity to show in CLI table.')
    return p

# ---------- Presentation helpers ----------

def severity_color(s: str) -> str:
    return Fore.RED if s == "high" else (Fore.YELLOW if s == "medium" else (Fore.GREEN if s == "low" else Fore.CYAN))

def print_table_header():
    # columns: PORT (6) SEV (8) SERVICE/BANNER (40) NOTE (max 70)
    print()
    print(f"{'PORT':<6} {'SEV':<8} {'SERVICE/BANNER':<40} {'NOTE'}")
    print('-' * (6 + 1 + 8 + 1 + 40 + 1 + 70))

# ---------- Main ----------

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.yes:
        print(f"{Fore.YELLOW}[!] Only scan hosts you own or have explicit permission to test. Use --yes to skip this message.{Style.RESET_ALL}\n")

    # Parse ports
    try:
        ports = parse_ports(args.ports)
        if not ports:
            print(f"{Fore.RED}[!] No valid ports to scan. Exiting.{Style.RESET_ALL}")
            return
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing ports: {e}{Style.RESET_ALL}")
        return

    # Resolve host
    try:
        target_ip = resolve_target(args.target)
    except Exception as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
        return

    print(f"Starting scan: {args.target} ({target_ip}), ports {ports[0]}-{ports[-1]} (count={len(ports)}), workers={args.workers}, timeout={args.timeout}")

    found, elapsed = scan_host(args.target, ports, args.workers, args.timeout, args.banner_size, args.no_noisy)

    # Build payload with security feedback
    meta = {"workers": args.workers, "timeout": args.timeout, "banner_size": args.banner_size, "no_noisy": args.no_noisy}
    payload = build_json_payload(args.target, target_ip, args.ports, ports, found, elapsed, meta)

    # Filter for CLI table according to min severity
    min_threshold = SEVERITY_ORDER.get(args.min_severity, 0)
    filtered = [entry for entry in payload["open_ports"] if SEVERITY_ORDER.get(entry["security_feedback"]["severity"], 0) >= min_threshold]

    # If no ports match, show a short message
    if not filtered:
        print(f"\n{Fore.RED}No open TCP ports matching severity >= '{args.min_severity}' on {args.target} ({target_ip}).{Style.RESET_ALL}")
    else:
        # Print full table header
        print_table_header()
        # Print rows (limit long fields)
        for entry in filtered:
            p = entry["port"]
            info = sanitize_banner(entry["info"], max_len=40)
            sec = entry["security_feedback"]
            sev = sec.get("severity", "info")
            note = sec.get("note", "")
            color = severity_color(sev)
            port_str = f"{p:<6}"
            sev_str = f"{sev.upper():<8}"
            info_str = f"{info:<40}"
            note_str = note
            print(f"{port_str} {color}{sev_str}{Style.RESET_ALL} {info_str} {note_str}")

    # Print summary line
    total_open = len(payload["open_ports"])
    print(f"\nSummary: {total_open} open ports (scan_time={payload['scan_time_seconds']}s) on {args.target} ({target_ip})")

    # JSON output
    if args.json:
        print("\n" + json.dumps(payload, indent=2))

    # Save JSON to file
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            print(f"{Fore.CYAN}[i] Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save results to {args.output}: {e}{Style.RESET_ALL}")

    # Save text report if requested
    if args.report:
        write_text_report(args.report, payload)


if __name__ == "__main__":
    main()
