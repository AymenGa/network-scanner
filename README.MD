# 🔍 Network Scanner  

A fast, multi-threaded TCP port scanner written in **Python**.  
This project demonstrates practical skills in socket programming, concurrency with `ThreadPoolExecutor`, and exporting scan results in **JSON/CSV** formats.  

✅ Built as part of my **CompTIA Security+** learning path.

![Python](https://img.shields.io/badge/Python-3.14-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

---

## ⚙️ Features  

- Scan target hosts for open **TCP ports** (single host or range)  
- Supports `common` preset ports and custom ranges (`1-1024`) or lists (`22,80,443`)  
- Multi-threaded scanning (`--workers`) for high speed  
- Adjustable socket `--timeout` for unreliable networks  
- Export results to **text**, **JSON**, or **CSV** (`--output`)  
- Colored console output and progress bars using `colorama` + `tqdm`  
- Severity notes for each open port for fast risk evaluation  
- Lightweight, easy to read and extend  

---

## 🛡️ Security Considerations  

- Uses full TCP connect scans (not SYN scans)  
- Does not attempt to bypass firewalls, IDS, or IPS  
- Results may be incomplete if the target applies rate-limiting (NIST SP 800‑115)  
- Severity notes help identify risky services  
- Strictly for **authorized testing** only  

---

## 🧪 Testing & Performance  

- Verified CLI arguments (`--target`, `--ports`, `--workers`, `--timeout`, `--banner-size`, `--json`, `--output`)  
- Performance benchmarked with 50–500 worker threads  
- Verified JSON export and CSV output correctness  
- Tested scanning unreachable hosts & closed ports  
- Checked long/short banners handling  
- Severity scoring validated for common risky ports  

---

## 📊 Port Report Example  

| PORT | SEVERITY | SERVICE/BANNER                        | NOTE                                                                 |
|------|----------|----------------------------------------|----------------------------------------------------------------------|
| 135  | INFO     | epmap                                  | Unknown service — review necessity if exposed externally.            |
| 445  | HIGH     | microsoft-ds                           | SMB — dangerous externally; block unless required.                  |
| 1337 | MEDIUM   | HTTP/1.1 400 Server: WebSocket++/0.8.2 | Web service — ensure patching and HTTPS.                            |
| 5040 | INFO     | open                                   | Unknown — verify configuration.                                     |
| 5357 | INFO     | wsd                                    | Windows service — validate exposure.                                |
| 7680 | INFO     | ms-do                                  | Unknown — review necessity.                                         |
| 7768 | INFO     | { "jsonrpc": "2.0", ... }              | Internal JSON‑RPC endpoint — likely internal use only.              |

---

## 🚀 Installation  

```bash
git clone https://github.com/AymenGa/Network-Scanner.git
cd Network-Scanner
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows PowerShell
# venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

requirements.txt should contain at least :
tqdm,colorama,requests,tabulate

---

## 🧩 Usage examples
```bash
  # Scan common ports on localhost
  python scanner.py --target 127.0.0.1 --ports common
  
  # Scan port range with custom workers and timeout
  python scanner.py --target 192.168.1.1 --ports 1-1024 --workers 100 --timeout 0.5
  
  # Save results to JSON
  python scanner.py --target 127.0.0.1 --ports 22,80 --output results.json
```

---

##📄 JSON Output Example
  {
    "target": "127.0.0.1",
    "time": "2025-11-06T14:23:42",
    "open_ports": [
      {"port": 22, "severity": "MEDIUM", "service": "ssh", "note": "Remote access — ensure strong auth."},
      {"port": 80, "severity": "MEDIUM", "service": "http", "note": "Ensure HTTPS and updated server."}
    ]
  }

---

## 💡 What I learned building this
  - Implementing TCP sockets (socket, connect_ex)
  - Multi-threading using ThreadPoolExecutor
  - Designing robust CLI tools with argparse
  - Basic banner grabbing for service detection
  - Building readable terminal output (tqdm + colorama)
  - Creating structured reports (notes + severity)
  - Exporting results to JSON/CSV and handling file output
  - following NIST/OWASP/CIS standards for safe scanning

This project connects my networking studies (CCNA) with practical cybersecurity programming experience as I prepare for CompTIA Security+.

---

##⚠️ Ethical Note

  Use this tool only on systems you own or have explicit permission to test.
  Unauthorized scanning may be illegal.

---

## 🛠️ Future improvements (planned)
  - Async version for high-performance scanning
  - Deeper service heuristics + better detection
  - Severity engine upgrade (CVE mapping)
  - Web dashboard (Flask) for visualizing results
  - Better testing suite (unit tests + CI)

---

## 👤 Author
Aymen Gasri — Computer Engineering Graduate (ISIMA Mahdia)
Preparing for CompTIA Security+ and MSc applications 
