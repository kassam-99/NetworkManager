# WiFi Network Manager

A powerful Python-based **WiFi and Network Management Toolkit** that provides automation, monitoring, spoofing, firewall control, and reporting functionalities.

This tool is built for **system administrators, penetration testers, researchers, and advanced users** who need to manage and analyze wireless and wired network environments.

---

## ✨ Features

### 🔹 Core Network Management

* List and auto-select active network interfaces
* Retrieve detailed interface statistics (MAC, IPv4, IPv6, status, packets, errors, etc.)
* Monitor configuration changes and auto-update settings
* Static IP configuration and DNS setup
* DHCP renew/release

### 🔹 Wi-Fi Management

* Scan and parse nearby Wi-Fi networks
* Connect to Wi-Fi networks (supports WPA/WEP)
* Save and load Wi-Fi profiles (`JSON` based)
* Auto-reconnect and roaming enhancement
* Suggest the least congested Wi-Fi channel
* Enable **Access Point (AP) Mode** with `hostapd` + `dnsmasq`
* List connected AP clients

### 🔹 Security & Spoofing

* Randomize MAC addresses
* Spoof IP addresses
* Auto-rotate MAC/IP periodically
* Reset spoofed addresses to defaults
* Flush & monitor ARP tables
* Detect ARP spoofing and conflicts
* IPTables firewall rules:

  * Flush rules
  * Block/unblock IPs
  * Block/allow ports
  * List current rules

### 🔹 Diagnostics

* Check Internet connectivity
* Run ICMP ping tests
* Run bandwidth speed test (via `speedtest-cli`)
* Monitor connection health and auto-reconnect

### 🔹 SSH Management

* Check if SSH service is available on hosts
* Test SSH login using credentials (`paramiko`)
* Configure local SSH server (install/start OpenSSH)
* Scan LAN for SSH-enabled devices

### 🔹 Wireless Modes

* Enable/disable monitor mode (`airmon-ng`)
* Set wireless channel

### 🔹 Profiles & Reporting

* Switch between saved network profiles (e.g., Home, Office)
* Save all network data into multiple formats:

  * CSV, TXT, JSON, XML, HTML, Markdown, PDF
* Logs all actions with a custom `Logger` module

---

## 📦 Dependencies

### ✅ Standard Libraries

* `threading`, `time`, `typing`, `copy`, `ipaddress`, `json`
* `os`, `random`, `re`, `socket`, `importlib`
* `subprocess`, `sys`

### ✅ Third-Party Libraries

* `netifaces`
* `paramiko`
* `psutil`
* `speedtest-cli` (imported as `speedtest`)
* `scapy`
* `reportlab` (used by `ReportRiser` for PDF export)

### ✅ Local Modules (included in this repo)

* `Logger.py` → Provides the `Logs` class for printing and logging
* `ReportRiser.py` → Provides the `Report_Generator` class for generating reports

---

## ⚙️ Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/kassam-99/NetworkManager.git
   cd NetworkManager
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   Or manually:

   ```bash
   pip install netifaces paramiko psutil speedtest-cli scapy reportlab
   ```

3. **Ensure required tools are installed** (Linux):

   ```bash
   sudo apt-get install -y net-tools wireless-tools iproute2 iw dnsmasq hostapd aircrack-ng openssh-server
   ```

---

## 🚀 Usage

### Run the interactive dashboard

The entry point is `Dashboard.py`, which launches the menu-driven interface.
Most features require root privileges (raw sockets, `iptables`, interface
changes), so run it with `sudo`:

```bash
sudo python3 Dashboard.py
```

`Wifi_NetworkManager.py` is the library module (the `Wifi_Manager` class) and is
not meant to be run directly.

### Example inside Python

```python
from Wifi_NetworkManager import Wifi_Manager

manager = Wifi_Manager()

# List network interfaces
manager.list_interfaces()

# Auto-select default interface
manager.auto_select_interface()

# Scan Wi-Fi networks
manager.parse_wifi_scan()

# Spoof random MAC and IP
manager.spoof_random_mac()
manager.spoof_random_ip()

# Start monitoring for ARP spoofing
manager.log_arp_spoofing()

# Run a speed test
manager.run_speed_test()

# Switch to "Office" profile
manager.switch_profile("Office")
```

---

## 📊 Reports

Data can be exported into:

* **CSV** → for spreadsheets
* **TXT** → plain logs
* **JSON/XML** → machine-readable formats
* **HTML/Markdown** → human-readable reports
* **PDF** → ready-to-share documentation

Example:

```python
manager.SaveData(manager.NetworkData, report_types=["csv", "json"])
```

---

## 🔒 Security Notes

* Many functions require **root privileges** (`sudo`).
* Be cautious with spoofing, firewall manipulation, and AP mode in **production environments**.
* ARP spoof detection is passive, but enabling AP mode or spoofing MAC/IP may disrupt active connections.
* The LAN/SSH scanning features (`scan_lan_for_ssh`, `basic_ssh_port_check`, `ssh_login_test`) should only be used on networks and hosts **you own or are explicitly authorized to test**. Unauthorized scanning or login attempts may be illegal in your jurisdiction.
* This tool is intended for **educational, security research, and administrative use only**. You are responsible for complying with all applicable laws and policies.

> **Note:** Saved Wi-Fi profiles are written to `Saved_WiFi_Profiles.json` in
> plaintext. This file is git-ignored — do not commit it, as it may contain
> Wi-Fi credentials.


---

## 🤝 Contributing

Contributions are welcome!

* Fork the repository
* Create a feature branch (`git checkout -b feature-name`)
* Commit changes (`git commit -m "Added feature XYZ"`)
* Push and open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** – feel free to use, modify, and distribute with attribution.

---

## 👨‍💻 Author

Developed by **Kassam Dakhlalah**

---


