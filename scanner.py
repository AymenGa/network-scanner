import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target, port, timeout=0.5):
    """Return (port, info) if open else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((target, port))
            if res == 0:
                # try small banner; may be empty
                try:
                    s.settimeout(0.4)
                    s.sendall(b"\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    service = ""
                info = banner or service or "open"
                return (port, info)
    except Exception:
        return None
    return None

if __name__ == "__main__":
    target = "127.0.0.1"
    ports = list(range(1, 201))   # small range to test
    workers = 50
    timeout = 0.4

    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = [exe.submit(scan_port, target, p, timeout) for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                port, info = res
                print(f"[+] {port}/tcp open  -- {info}")
                open_ports.append((port, info))

    print("\nScan complete.")
    print("Open ports:", sorted(open_ports))
