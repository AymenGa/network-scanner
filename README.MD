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
- Lightweight, easy to read and extend  

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
requirements.txt should contain at least:
tqdm, colorama, requests, tabulate

---

## 🧩 Usage examples
```bash
Copy code
# Scan common ports on localhost
python scanner.py --target 127.0.0.1 --ports common

# Scan a custom range, change concurrency and timeout
python scanner.py --target 192.168.1.1 --ports 1-1024 --workers 100 --timeout 0.5

# Save results in JSON
python scanner.py --target 127.0.0.1 --ports 22,80 --output results.json
```
---

Example console output
```sql
Copy code
[+] 22/tcp open  -- ssh
[+] 80/tcp open  -- http
Scan complete in 3.21s
Open ports: [(22,'ssh'), (80,'http')]
```
---

📄 JSON output example (results.json)
```json
{
  "target": "127.0.0.1",
  "time": "2025-11-06T14:23:42",
  "open_ports": [
    {"port": 22, "info": "ssh"},
    {"port": 80, "info": "http"}
  ]
}
```
---

## 💡 What I learned building this
  - Practical use of TCP sockets (socket, connect_ex) for port probing
  - Concurrency in Python with ThreadPoolExecutor and collecting results (as_completed)
  - Designing a small CLI using argparse with sensible defaults (--workers, --timeout)
  - Exporting structured data to JSON and CSV for later analysis
  - Simple banner grabbing and service detection basics
  - UX polish with tqdm progress bars and colored terminal output (colorama)

This project connects my networking studies (CCNA) with practical cybersecurity programming experience as I prepare for CompTIA Security+.

---

## ⚠️ Ethical note
This tool is for educational and authorized testing only.
Do NOT scan systems you do not own or do not have explicit permission to test.
Unauthorized scanning may be illegal or could get your IP blocked.

---

## 🛠️ Future improvements (planned)
  - Add an asyncio implementation for higher concurrency
  - Improve service detection with targeted probes and heuristics
  - Add unit tests and continuous integration (GitHub Actions)
  - Build a simple web dashboard (Flask) to visualize scan results

---

## 👤 Author
Aymen Gasri — Computer Engineering Graduate (ISIMA Mahdia)
Preparing for CompTIA Security+ and MSc applications 
