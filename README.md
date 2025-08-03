🔍 Nmap Recon + Attack Suggestion Tool

A Python-based cybersecurity automation tool that performs advanced Nmap scans, parses the XML output, maps detected services to potential vulnerabilities, and provides intelligent suggestions for attack techniques — all wrapped in a clean, shareable HTML report.

> 📌 Built for red teamers, pentesters, bug bounty hunters, and ethical hackers who want **quick recon + actionable insights**.

---

📌 Key Features

- ✅ **Automated Nmap Scanning**:
  - `-sC`: Default scripts
  - `-sV`: Version detection
  - `-O`: OS detection
  - `--script vuln`: Common vulnerability scripts
- 🧠 **Service-to-Vulnerability Mapping**:
  - Matches open ports/services to known CVEs and misconfigurations
- 🧰 **Attack Tool Suggestions**:
  - Suggests tools like Hydra, sqlmap, enum4linux, Metasploit modules, etc.
- 📄 **HTML Report Generation**:
  - Human-readable report for sharing, archiving, or reviewing findings

---

🛠️ How It Works

```text
User enters target IP/subnet
        ↓
Tool runs Nmap with vuln detection
        ↓
Parses the Nmap XML result
        ↓
Looks up known vulns and attack tools for open services
        ↓
Generates a beautiful HTML report
