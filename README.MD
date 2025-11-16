##🔍 Network Scanner

A fast, multi-threaded TCP port scanner written in Python.
This project demonstrates real-world defensive security skills, including socket programming, concurrency, safe banner grabbing, and structured reporting.

Built as part of my CompTIA Security+ and networking/security engineering learning path.

---

#⚙️ Features

  Scan a single target for open TCP ports
  
  Supports:
  
  common preset ports
  
  custom ranges (1-1024)
  
  custom lists (22,80,443)
  
  Multi-threaded scanning with ThreadPoolExecutor
  
  Adjustable --timeout, --workers, and --banner-size
  
  Colored console output + clean formatted table
  
  Severity ranking for each open port (INFO / MEDIUM / HIGH)
  
  Clear notes for every service and banner
  
  Export results to JSON, CSV, or TXT using --output
  
  Lightweight, easy to maintain, and fully CLI-driven

---

#🚀 Installation
  git clone https://github.com/AymenGa/Network-Scanner.git
  cd Network-Scanner
  python -m venv venv
  # Linux/Mac
  source venv/bin/activate
  # Windows PowerShell
  # venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  
  
  requirements.txt
  
  tqdm
  colorama
  requests
  tabulate

---

#🧩 Usage Examples
  # Scan common ports on localhost
  python scanner.py --target 127.0.0.1 --ports common
  
  # Scan port range with custom workers and timeout
  python scanner.py --target 192.168.1.1 --ports 1-1024 --workers 100 --timeout 0.5
  
  # Save results to JSON
  python scanner.py --target 127.0.0.1 --ports 22,80 --output results.json

---

#📊 Example Console Output
  PORT   SEV      SERVICE/BANNER                        NOTE
  -----------------------------------------------------------------------
  445    HIGH     microsoft-ds                          SMB — high risk if exposed externally.
  1337   MEDIUM   HTTP/1.1 400 Server: WebSocket++     Web service — check version & HTTPS.
  5357   INFO     wsd                                   Unknown service — review exposure.

---

#📄 JSON Output Example
  {
    "target": "127.0.0.1",
    "time": "2025-11-06T14:23:42",
    "open_ports": [
      {"port": 22, "severity": "MEDIUM", "service": "ssh", "note": "Remote access — ensure strong auth."},
      {"port": 80, "severity": "MEDIUM", "service": "http", "note": "Ensure HTTPS and updated server."}
    ]
  }

---

#🛡️ Security Considerations

  This scanner is intentionally safe, legal, and non-intrusive.
  It does NOT try to evade firewalls or perform aggressive techniques.
  References included for credibility.
  
  1️⃣ Full TCP Connect Scan
  
  Uses full 3-way handshake, safe and standard.
  
  Does not perform stealth SYN scans.
  📖 Ref: NIST SP 800‑115
  
  2️⃣ No Firewall/IDS Evasion
  
  No packet fragmentation
  
  No spoofing
  
  No obfuscation or IDS bypassing
  📖 Ref: OWASP Network Scanning Guide
  
  4️⃣ Subject to Rate-Limiting / IDS
  
  Firewalls and IDS can hide open ports.
  📖 Ref: CISA IDS Guide
  
  6️⃣ Severity Levels (Implemented)
  
  Based on CIS hardening logic:
  
  High → SMB, RDP, SSH exposed externally
  
  Medium → Web ports, API ports
  
  Info → Unknown or internal services
  📖 Ref: CIS Controls v8
  
  7️⃣ Safe Banner Grabbing
  
  Only performs a single lightweight recv()
  
  No aggressive probing, no fuzzing
  📖 Ref: NIST SP 800‑115 (Banner Grabbing)
  
  8️⃣ Privacy & OPSEC
  
  The tool does not store logs or metadata
  
  Output files contain scan results only
  📖 Ref: OWASP Logging Cheat Sheet
  
  9️⃣ No Deep Enumeration
  
  Does not fingerprint OS, versions, or CVEs
  
  Keeps scanning fast, safe, and compliant
  📖 Ref: Nmap Port Scanning Techniques

---

#🧪 Testing Performed
  ✔️ CLI Argument Validation
  
  Successfully tested:
  --target, --ports, --workers, --timeout, --banner-size, --output, --json
  
  ✔️ Threading & Performance
  
  Tested 50 → 1000 workers
  
  Verified that thread pool execution remains stable
  
  No thread starvation or lockups
  
  ✔️ Banner Grabbing
  
  Works with short banners (SMB, epmap…)
  
  Works with long banners (WebSocket++, JSON-RPC…)
  
  Ensures safe truncation using --banner-size
  
  ✔️ Reporting Table
  
  Severity colors render correctly
  
  Notes are aligned and readable
  
  Services detected using mapping + banners
  
  ✔️ Export Formats
  
  JSON validated
  
  CSV validated
  
  TXT is human-readable

---

#💡 What I Learned

  Implementing TCP sockets (socket, connect_ex)
  
  Multi-threading using ThreadPoolExecutor
  
  Designing robust CLI tools with argparse
  
  Basic banner grabbing for service detection
  
  Building readable terminal output (tqdm + colorama)
  
  Creating structured reports (notes + severity)
  
  Exporting results to JSON/CSV and handling file output
  
  Following NIST/OWASP/CIS standards for safe scanning

---

#⚠️ Ethical Note

  Use this tool only on systems you own or have explicit permission to test.
  Unauthorized scanning may be illegal.

---

#🛠️ Future Improvements

  Async version for high-performance scanning
  
  Deeper service heuristics + better detection
  
  Severity engine upgrade (CVE mapping)
  
  Web dashboard (Flask) for visualizing results
  
  Better testing suite (unit tests + CI)

---

## 👤 Author
Aymen Gasri — Computer Engineering Graduate (ISIMA Mahdia)
Preparing for CompTIA Security+ and MSc applications 
