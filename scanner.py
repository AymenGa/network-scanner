#!/usr/bin/env python3


from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import argparse
import time
import json
from typing import List, Tuple, Optional, Dict

# Defaults / presets
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 0.4
DEFAULT_BANNER = 256
PRESETS = {
    'fast': '1-1024',
    'common': '1-1024,3306,8080',
    'full': '1-65535'
}

# ----------------------------
# Port parsing
# ----------------------------
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

# ----------------------------
# Resolve and banner helpers
# ----------------------------
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

def attempt_banner(sock: socket.socket, max_bytes: int, default_timeout: float) -> str:
    try:
        sock.settimeout(min(0.25, sock.gettimeout() or default_timeout))
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
            banner = attempt_banner(s, banner_size, timeout)
            service = try_get_service(port) or ""
            info = banner or service or "open"
            return (port, info)
    except Exception:
        return None

# ----------------------------
# Scanning core
# ----------------------------
def scan_host(target: str, ports: List[int], workers: int, timeout: float, banner_size: int) -> Tuple[List[Tuple[int, str]], float]:
    target_ip = resolve_target(target)
    results: List[Tuple[int, str]] = []
    total = len(ports)
    checked = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=workers) as exe:
        # Build futures with a simple for-loop for readability
        futures_map = {}
        for p in ports:
            fut = exe.submit(scan_port_once, target_ip, p, timeout, banner_size)
            futures_map[fut] = p

        # Process as they complete
        for fut in as_completed(futures_map):
            checked += 1
            port = futures_map[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                results.append(res)
                # Human output printed by caller if desired
                print(f"[+] {res[0]}/tcp open  -- {res[1]}")
            # Lightweight progress update every ~10% or at end
            if total <= 20 or checked % max(1, total // 10) == 0 or checked == total:
                print(f"[i] Progress: {checked}/{total} ports checked")

    elapsed = time.time() - start
    results.sort()
    print(f"[i] Scan completed in {elapsed:.2f}s — {len(results)} open ports found")
    return results, elapsed

# ----------------------------
# JSON payload builder
# ----------------------------
def build_json_payload(target: str, target_ip: str, ports_spec: str, ports_list: List[int],
                       found: List[Tuple[int, str]], elapsed: float, meta: Dict) -> Dict:
    return {
        "target": target,
        "resolved_ip": target_ip,
        "ports_requested": ports_spec,
        "ports_scanned": len(ports_list),
        "open_ports": [{"port": p, "info": info} for p, info in found],
        "scan_time_seconds": round(elapsed, 3),
        "meta": meta
    }

# ----------------------------
# CLI
# ----------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Threaded TCP scanner with optional JSON output and file saving.")
    p.add_argument('-t', '--target', required=True, help='Target hostname or IPv4 address.')
    p.add_argument('-p', '--ports', default='common', help='Ports: preset (fast|common|full) or list/range (22,80,1-1024).')
    p.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, help=f'Worker threads (default {DEFAULT_WORKERS}).')
    p.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help=f'Timeout seconds (default {DEFAULT_TIMEOUT}).')
    p.add_argument('--banner-size', type=int, default=DEFAULT_BANNER, help=f'Max banner bytes (default {DEFAULT_BANNER}).')
    p.add_argument('--yes', action='store_true', help='Skip permission reminder.')
    p.add_argument('--json', action='store_true', help='Print JSON output after scan.')
    p.add_argument('-o', '--output', help='Save JSON results to file (path).')
    return p

# ----------------------------
# Main
# ----------------------------
def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.yes:
        print("[!] Only scan hosts you own or have explicit permission to test. Use --yes to skip this message.\n")

    # Parse ports
    try:
        ports = parse_ports(args.ports)
        if not ports:
            print("No valid ports to scan. Exiting.")
            return
    except Exception as e:
        print(f"Error parsing ports: {e}")
        return

    # Resolve host
    try:
        target_ip = resolve_target(args.target)
    except Exception as e:
        print(e)
        return

    # Announce and scan
    print(f"Starting scan: {args.target} ({target_ip}), ports {ports[0]}-{ports[-1]} (count={len(ports)}), workers={args.workers}, timeout={args.timeout}")
    found, elapsed = scan_host(args.target, ports, args.workers, args.timeout, args.banner_size)

    # Human summary (always show, JSON printing optional)
    if not found:
        print(f"\nNo open TCP ports found on {args.target} ({target_ip}).")
    else:
        items = [f"{p}({info.split()[0] if info else 'open'})" for p, info in found[:10]]
        more = f" +{len(found)-10} more" if len(found) > 10 else ""
        print(f"\nSummary: {len(found)} open ports on {args.target} ({target_ip}): " + ", ".join(items) + more)

    # Build JSON payload
    if args.json or args.output:
        meta = {
            "workers": args.workers,
            "timeout": args.timeout,
            "banner_size": args.banner_size
        }
        payload = build_json_payload(args.target, target_ip, args.ports, ports, found, elapsed, meta)

    # Print JSON to stdout only if requested
    if args.json:
        print("\n" + json.dumps(payload, indent=2))

    # Save to file if requested
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            print(f"[i] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save results to {args.output}: {e}")


if __name__ == '__main__':
    main()
