# W.E.A.P.O.N.
> **Wireless Exploitation Access Persistence Obfuscation & Navigation**
<p align="center">
  <img src="https://github.com/user-attachments/assets/dc0fe0ae-af13-410c-85ca-f0d198d752ae" width="600" alt="W.E.A.P.O.N. logo">
</p>
> :warning: Early stage release
### 👤 Author: WebDragon63  
### 🎯 Purpose: A modular Python-based red team framework for offensive operations.

---

## 🔥 Overview

**W.E.A.P.O.N.** is a powerful red team toolkit that brings together essential capabilities for offensive security:
- Wireless attacks
- Exploitation modules (PoCs and CVEs)
- Persistence
- Obfuscation engines
- Credential and system access
- Navigation and recon
- Beacon payload generation
- Custom loader creation
- Teamserver with interactive shell
- Full encryption support



## 🧠 Modules

| Category      | Command Name     | Description                                 |
|---------------|------------------|---------------------------------------------|
| Access        | `access`         | Local and remote access tools               |
| Wireless      | `wireless`       | Wireless scanning & injection               |
| Exploitation  | `exploit`        | CVE and buffer overflow launcher            |
| Persistence   | `persist`        | Add registry/cron persistence techniques    |
| Obfuscation   | `obfuscate`      | Encode, obfuscate, and disguise payloads    |
| Navigation    | `navigation`     | OSINT, recon, port scans, etc.              |
| Beacon        | `beacon`         | Generate beacon script or obfuscated beacon |
| Crypto        | `aes`, `chacha`, `xor`, `keygen` | Encryption/decryption utilities |
| Loaders       | `loader_exe`, `loader_hta`, `loader_macro`, `loader_ps` | Payload delivery mechanisms |

---

## 🚀 Getting Started

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
### 2. Launch the framework
```bash
python3 weapon_gui.py
```
![Screenshot at 2025-06-18 23-12-03](https://github.com/user-attachments/assets/37ae4195-81c2-4e3b-9813-3acdd00dc9fb)

🛡 Disclaimer
This project is intended for educational and authorized penetration testing purposes only.
Misuse of this tool can lead to criminal charges. You are solely responsible for your actions.


