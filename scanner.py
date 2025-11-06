import socket

def scan_port(target, port, timeout=0.5):
    """Return True if open, False otherwise."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((target, port))
        s.close()
        return res == 0
    except Exception:
        return False

if __name__ == "__main__":
    target = "127.0.0.1"
    ports = [22, 80, 135, 443]  # quick list you can edit
    open_ports = []
    for p in ports:
        if scan_port(target, p):
            print(f"[+] {p} OPEN")
            open_ports.append(p)
        else:
            print(f"[-] {p} closed")
    print("Open ports:", open_ports)
