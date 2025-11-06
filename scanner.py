#!/usr/bin/env python3
"""
Step 4 (CLI): Threaded TCP scanner with a simple command-line interface.

This version is intentionally written in a more readable, "normal" style:
we build the futures mapping with a simple for-loop instead of a dict-comprehension.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import argparse
import time
from typing import List, Tuple, Optional

DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 0.4
DEFAULT_BANNER = 256
PRESETS = {
    'fast': '1-1024',
    'common': '1-1024,3306,8080',
    'full': '1-65535'
}

# ----- Helpers -----
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
                if a > b: a, b = b, a
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

def attempt_banner(sock: socket.socket, max_bytes: int) -> str:
    try:
        sock.settimeout(min(0.25, sock.gettimeout() or DEFAULT_TIMEOUT))
        try:
            sock.sendall(b"\r\n")
        except Exception:
            pass
        data = sock.recv(max_bytes)
        return data.decode(errors='ignore').strip() if data else ""
    except Exception:
        return ""

def scan_port_once(ip: str, port: int, timeout: float, banner_size: int) -> Optional[Tuple[int, str]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = attempt_banner(s, banner_size)
            service = try_get_service(port) or ""
            info = banner or service or "open"
            return (port, info)
    except Exception:
        return None

# ----- Scanning core -----
def scan_host(target: str, ports: List[int], workers: int, timeout: float, banner_size: int) -> List[Tuple[int, str]]:
    target_ip = resolve_target(target)
    results: List[Tuple[int, str]] = []
    total = len(ports)
    checked = 0
    start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as exe:
        # build futures mapping in a simple, readable way
        futures_map = {}
        for p in ports:
            fut = exe.submit(scan_port_once, target_ip, p, timeout, banner_size)
            futures_map[fut] = p

        # process results as they complete
        for fut in as_completed(futures_map):
            checked += 1
            port = futures_map[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                results.append(res)
                print(f"[+] {res[0]}/tcp open  -- {res[1]}")
            # lightweight progress update every 10% or at end
            if total <= 20 or checked % max(1, total // 10) == 0 or checked == total:
                print(f"[i] Progress: {checked}/{total} ports checked")
    elapsed = time.time() - start
    results.sort()
    print(f"[i] Scan completed in {elapsed:.2f}s — {len(results)} open ports found")
    return results

# ----- CLI -----
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Step 4 CLI: threaded TCP scanner (no JSON yet).")
    p.add_argument('-t', '--target', required=True, help='Target hostname or IPv4 address.')
    p.add_argument('-p', '--ports', default='common', help='Ports to scan: preset (fast|common|full) or list/range (22,80,1-1024).')
    p.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, help=f'Number of worker threads (default {DEFAULT_WORKERS}).')
    p.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help=f'Socket timeout in seconds (default {DEFAULT_TIMEOUT}).')
    p.add_argument('--banner-size', type=int, default=DEFAULT_BANNER, help=f'Max banner bytes to read (default {DEFAULT_BANNER}).')
    p.add_argument('--yes', action='store_true', help='Skip permission reminder (only use if authorized).')
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.yes:
        print("[!] Only scan hosts you own or have explicit permission to test. Use --yes to skip this message if you have authorization.\n")

    try:
        ports = parse_ports(args.ports)
        if not ports:
            print("No ports parsed. Exiting.")
            return
    except Exception as e:
        print(f"Error parsing ports: {e}")
        return

    try:
        target_ip = resolve_target(args.target)
    except Exception as e:
        print(e)
        return

    print(f"Starting scan: {args.target} ({target_ip}), ports {ports[0]}-{ports[-1]} (count={len(ports)}), workers={args.workers}, timeout={args.timeout}")
    found = scan_host(args.target, ports, workers=args.workers, timeout=args.timeout, banner_size=args.banner_size)

    # human summary
    if not found:
        print(f"\nNo open TCP ports found on {args.target} ({target_ip}).")
    else:
        items = [f"{p}({info.split()[0] if info else 'open'})" for p, info in found[:10]]
        more = f" +{len(found)-10} more" if len(found) > 10 else ""
        print(f"\nSummary: {len(found)} open ports on {args.target} ({target_ip}): " + ", ".join(items) + more)

if __name__ == '__main__':
    main()
