# RANSENTRY | Behavioral Ransomware Early Warning System (EDR)

<p align="center">
  <img src="ransentry_logo.png" alt="RANSENTRY Logo" width="220"/>
</p>

<p align="center">
  <strong>See Threats. Stop Damage. Stay Secure.</strong><br>
  <em>An interactive Endpoint Detection and Response (EDR) simulator featuring heuristic risk scoring, time decay, deception honeypots, machine learning inference, and tamper-evident audit logging.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?logo=python" alt="Python Version"/>
  <img src="https://img.shields.io/badge/UI-ttkbootstrap-purple" alt="ttkbootstrap"/>
  <img src="https://img.shields.io/badge/Visualization-Matplotlib-orange" alt="Matplotlib"/>
  <img src="https://img.shields.io/badge/ML-Scikit--Learn-yellow" alt="Scikit-Learn"/>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"/>
</p>

---

## Overview

**RANSENTRY** simulates early-stage ransomware activity and defensive incident response on an endpoint. Rather than relying solely on static signature detection, RANSENTRY demonstrates modern behavioral heuristics: tracking suspicious activity sequences, applying real-time exponential decay to benign actions, monitoring decoy honeypot files with filesystem hooks, and querying live threat intelligence feeds.

---

## Core Features & Modules

1. **Heuristic Risk Engine with Time Decay**
   - Evaluates process behavior types: `Mass_File_Read`, `File_Rename_Op`, `Encrypting_Operation`, `Delete_Backups`, `Security_Disable`.
   - Dynamic 10-second sliding decay window auto-expires isolated benign actions.

2. **Real-Time Visual Threat Telemetry**
   - Embedded dark-mode Matplotlib canvas plotting the live risk score trajectory, danger thresholds, and attack lifecycles.

3. **Honeypot Deception Environment**
   - Deploys canary decoy files (`passwords_backup.xlsx`, `financial_report_2025.html`, etc.) in `honeypot_files/`.
   - Real-time filesystem hooks (`watchdog`) instantly alert when unauthorized processes touch decoy assets.

4. **Tamper-Evident Hash-Chain Audit Trail**
   - SHA-256 cryptographic blockchain-style log records all events.
   - Built-in integrity verification detects retroactive log tampering.

5. **Machine Learning Behavioral Classification**
   - Random Forest classifier trained on rolling 20-action operation sequences to autonomously identify attack patterns.

6. **Live Threat Intelligence Integration**
   - Connects to the URLhaus recent threat feed to adjust detection sensitivity multipliers during active ransomware campaigns.

7. **Interactive SOC Incident Dispatch Center**
   - Dispatch structured JSON alert payloads formatted for Tier-2 SOC teams, webhooks, or SIEM endpoints.

8. **Dynamic 3-Tier Security Knowledge Quiz**
   - Interactive security awareness quiz with Easy, Medium, and Hard difficulty tiers and instant feedback.

---

## Installation & Setup

### Prerequisites
- Python 3.9 or higher

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/ransentry.git
cd ransentry
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run RANSENTRY
```bash
python Ransomware.py
```
*Or double-click `run.bat` on Windows.*

---

## Project Structure

```
Ransomware Early Warning System/
├── Ransomware.py               # Main application and GUI engine
├── Ransom info.html            # Documentation & project overview page
├── README.md                   # Repository overview and setup guide
├── requirements.txt            # Python dependencies
├── run.bat                     # Windows quick-launch script
├── ransentry_logo.png          # UI Logo
├── ransentry_icon.ico          # Application window icon
└── honeypot_files/             # Canary decoy files monitored by Watchdog
```

---

## Authors & Credits

Developed by:
- **Pathan Basheer Khan** — *Cybersecurity Developer & Security Awareness Coordinator* (ST#IS#9780)
- **Choppa Haritha** — *Lead EDR System Architect & Threat Analytics Specialist* (ST#IS#9760)

---

## Ethical Research Disclaimer

*RANSENTRY is an educational and defensive cybersecurity simulator created strictly for research, security training, and defensive posture evaluation. It runs in a self-contained, benign environment and must never be used for unauthorized testing.*
