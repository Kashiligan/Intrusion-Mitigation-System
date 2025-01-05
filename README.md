## Intrusion Mitigation System

🔍 **Overview**:  
A Python-based system designed to enhance network security by analyzing real-time network traffic, detecting anomalies (e.g., port scanning), and mitigating threats by blocking suspicious IPs using `iptables`.

🛠️ **Features**:  
- Real-time packet capture and analysis using **Scapy**.
- Detection of port scans and other suspicious activities.
- Automatic blocking of malicious IPs using **iptables**.
- Logging of detected threats and actions for further analysis.

🚀 **Tech Stack**:  
- Python | Scapy | iptables | Linux
- Logging and reporting for threat analysis.

📂 **How to Use**:  
1. Install dependencies:  
   ```bash
   sudo apt install python3-scapy

2. Give Root Privileges:
   ```bash
   sudo chmod +x Intrusion-Mitigation.py

3. Run with sudo:
   ```bash
   sudo ./Intrusion-Mitigation.py
