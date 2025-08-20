# Standard library imports
import copy
import ipaddress
import json
import os
import random
import re
import socket
import importlib
import subprocess
import sys
import threading
import time

# Third-party imports
import netifaces
import paramiko
import psutil
import speedtest
from scapy.all import ARP, Ether, srp
from typing import Dict, List, Optional

# Local imports
from Logger import Logs
from ReportRiser import Report_Generator






































class Wifi_Manager:
    def __init__(self):
        self.Reporter = Report_Generator()
        self.Logger_Functions = Logs()
        self.Logger_Functions.LogEngine("NetworkManager_Logs", "Wifi_Manager")
        self.config_lock = threading.Lock()  
        
        
        self.NetworkData = {
            "IPv4_Network": None,
            "IPv4_Subnet": None,
            "IPv4_Broadcast": None,
            "Private_IPv4": None,
            "Public_IPv4": None,
            "IPv4_Total_Hosts": None,
            "IPv4_Usable_Hosts": None,
            "IPv4_Usable_Range": None,
            "IPv6_Network": None,
            "IPv6_Prefix_Length": None,
            "Private_IPv6": None,
            "IPv6_Total_Addresses": None,
            "Network_Interface": None,
            "MAC_Address": None,
            "Default_Gateway_IPv4": None,
            "Default_Gateway_MAC": None,
            "Default_Gateway_IPv6": None          
        }
        
        self.Main_Config = {
            "Default Network Interface": None,
            "Default IP Address": None,
            "Default MAC Address": None,
            "Default Port": None,
            "Default Protocol": None,
            "Spoofed IP Address": None,
            "Spoofed MAC Address": None,
            "Spoofed Port": None,
            "Spoofed Protocol": None,
            "List of Network Interfaces (Names)": None,
            "List of Network Interfaces (Status)": None,
            "List of Network Interfaces (MAC Addresses)": None,
            "List of Network Interfaces (IPv4 Addresses)": None,
            "List of Network Interfaces (IPv6 Addresses)": None,
            "Auto Rotation Enabled": False,
        }

        self.Network_Profiles = {
            "Office": {
                "ip": None,
                "netmask": None,
                "gateway": None
            },
            "Home": {
                "ip": None,
                "netmask": None,
                "gateway": None
            }
        }

        self.Saved_WiFi_Profiles = {}
        self.disconnect_monitor_thread = None
        

        # Standard libraries (already included in Python)
        self.standard_libs = [
            "threading", "time", "typing", "copy", "ipaddress", "json", 
            "os", "random", "re", "socket", "importlib", "subprocess", "sys"
        ]


        # Third-party libraries that may need installation
        self.third_party_libs = {
            "netifaces": "netifaces",
            "paramiko": "paramiko",
            "psutil": "psutil",
            "speedtest": "speedtest-cli",  # pip package name is different
            "scapy": "scapy"
        }
        
        
        self.set_default_config()  # Set a default config at initialization
        self.load_wifi_profiles()  # Load profiles at initialization
    



    def check_and_install(self, package_name, pip_name=None):
        try:
            importlib.import_module(package_name)
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] {package_name} is already installed.")
        except ImportError:
            self.Logger_Functions.print_and_log(f"[\u001b[32m~\u001b[0m] {package_name} not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name or package_name])
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] {package_name} installed successfully.")




    def verify_standard_libs(self):
        for pkg in self.standard_libs:
            try:
                importlib.import_module(pkg)
                self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] {pkg} is available (standard library).")
            except ImportError:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] {pkg} is missing, but it should be included with Python.")




    def run_check(self):
        # Check third-party libs
        for pkg, pip_pkg in self.third_party_libs.items():
            self.check_and_install(pkg, pip_pkg)

        # Verify standard libs
        self.verify_standard_libs()



    
    def SaveData(self, data_dict: Dict, report_types: Optional[List[str]] = None, metadata: Optional[Dict] = None, output_dir: Optional[str] = None):
        """
        Saves a given dictionary of data to one or more report formats using Report_Generator.
    
        Args:
            data_dict: Dictionary containing the data to be saved.
            report_types: Optional list of report types (e.g., ['csv', 'txt']). If None, saves to all formats.
            metadata: Optional dictionary of metadata to include in the report.
            output_dir: Optional directory to save the reports.
        """
        # Convert single dict to list of dicts
        data_list = [data_dict]
    
        # Validate Reporter
        if not hasattr(self, 'Reporter') or not isinstance(self.Reporter, Report_Generator):
            print("[\033[31m!\u001b[0m] Reporter not initialized or invalid.")
            return
    
        # Supported report types and their corresponding methods
        report_map = {
            "csv": self.Reporter.CSV_GenerateReport,
            "txt": self.Reporter.TXT_GenerateReport,
            "json": self.Reporter.JSON_GenerateReport,
            "xml": self.Reporter.XML_GenerateReport,
            "html": self.Reporter.HTML_GenerateReport,
            "md": self.Reporter.MD_GenerateReport,
            "pdf": self.Reporter.PDF_GenerateReport,
        }
    
        # Use all report types if none are specified
        report_types = report_types or list(report_map.keys())
        if "all" in report_types:
            report_types = list(report_map.keys())
    
        for rtype in report_types:
            rtype_lower = rtype.lower()
            generator = report_map.get(rtype_lower)
            if generator:
                try:
                    generator(
                        Data=data_list,
                        interactive=False,
                        custom_metadata=metadata,
                        output_dir=output_dir
                    )
                except Exception as e:
                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Failed to generate {rtype_lower} report: {e}")
            else:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Unsupported report type: {rtype}")
     
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Interface Management --------------------
    
    def list_interfaces(self):
        interfaces = netifaces.interfaces()
        self.Main_Config["List of Network Interfaces (Names)"] = interfaces
        self.Main_Config["List of Network Interfaces (MAC Addresses)"] = []
        self.Main_Config["List of Network Interfaces (IPv4 Addresses)"] = []
        self.Main_Config["List of Network Interfaces (IPv6 Addresses)"] = []  # New for IPv6
        self.Main_Config["List of Network Interfaces (Status)"] = []
    
        for iface in interfaces:
            try:
                addrs = netifaces.ifaddresses(iface)
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
    
                ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'N/A')
    
                # Get first global or unique local IPv6 (ignore link-local fe80::)
                ipv6_list = addrs.get(netifaces.AF_INET6, [])
                ipv6 = "N/A"
                for addr in ipv6_list:
                    ip6 = addr.get('addr', '')
                    if ip6 and not ip6.startswith("fe80"):  # skip link-local
                        ipv6 = ip6.split('%')[0]  # remove zone index if present
                        break
    
                status = 'UP' if psutil.net_if_stats().get(iface, None) and psutil.net_if_stats()[iface].isup else 'DOWN'
    
                self.Main_Config["List of Network Interfaces (MAC Addresses)"].append(mac)
                self.Main_Config["List of Network Interfaces (IPv4 Addresses)"].append(ipv4)
                self.Main_Config["List of Network Interfaces (IPv6 Addresses)"].append(ipv6)
                self.Main_Config["List of Network Interfaces (Status)"].append(status)
    
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] {iface}: {mac} @ IPv4:{ipv4} IPv6:{ipv6} [{status}]")
    
            except Exception as e:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error reading interface {iface}: {e}")    
    



    def auto_select_interface(self):
        names = self.Main_Config.get("List of Network Interfaces (Names)", [])
        statuses = self.Main_Config.get("List of Network Interfaces (Status)", [])
        ips = self.Main_Config.get("List of Network Interfaces (IPv4 Addresses)", [])
        macs = self.Main_Config.get("List of Network Interfaces (MAC Addresses)", [])

        for i in range(len(names)):
            iface = names[i]
            if statuses[i] == "UP" and not ips[i].startswith("127."):
                self.Main_Config["Default Network Interface"] = iface
                self.Main_Config["Default IP Address"] = ips[i]
                self.Main_Config["Default MAC Address"] = macs[i]
                self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Auto-selected default interface: {iface}")
                return

        self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No valid interface found to auto-select.")    
  



    def enable_interface(self, iface):
        import subprocess
        subprocess.call(["sudo", "ifconfig", iface, "up"])




    def disable_interface(self, iface):
        import subprocess
        subprocess.call(["sudo", "ifconfig", iface, "down"])   
    



    def show_interface_stats(self):
        import psutil
        stats = psutil.net_io_counters(pernic=True)
        for iface, data in stats.items():
            self.Logger_Functions.print_and_log(f"\n[\u001b[34m+\u001b[0m] Interface: {iface}")
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Bytes Sent: {data.bytes_sent}")
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Bytes Received: {data.bytes_recv}")
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Packets Sent: {data.packets_sent}")
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Packets Received: {data.packets_recv}")
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Errors In: {data.errin}, Errors Out: {data.errout}")
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Drop In: {data.dropin}, Drop Out: {data.dropout}")   
  



    def get_interface_addresses(self, iface):
        """
        Returns a dictionary with addresses and status for the given network interface,
        while also printing the details in the same style as show_interface_stats.
        """
        info = {
            "mac": None,
            "ipv4": None,
            "ipv6": None,
            "status": "DOWN"
        }
        
        try:
            addrs = netifaces.ifaddresses(iface)
    
            self.Logger_Functions.print_and_log(f"\n[\u001b[34m+\u001b[0m] Interface: {iface}")
    
            # MAC Address (AF_LINK)
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr')
            if mac:
                info["mac"] = mac
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] MAC Address: {mac}")
    
            # IPv4 Address (AF_INET)
            ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr')
            if ipv4:
                info["ipv4"] = ipv4
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv4 Address: {ipv4}")
    
            # IPv6 Address (AF_INET6) - skip link-local addresses (fe80::/10)
            ipv6_list = addrs.get(netifaces.AF_INET6, [])
            for addr in ipv6_list:
                ip6 = addr.get('addr', '').split('%')[0]  # Remove %zone if present
                if ip6 and not ip6.lower().startswith('fe80'):
                    info["ipv6"] = ip6
                    self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv6 Address: {ip6}")
                    break  # Use first global IPv6 found
    
            # Interface status via psutil
            stats = psutil.net_if_stats().get(iface)
            if stats and stats.isup:
                info["status"] = "UP"
            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Status: {info['status']}")
    
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error fetching addresses for {iface}: {e}")
        
        return info
    
         
         
     
     
    def set_default_config(self) -> None:
        """
        Automatically sets default values for Main_Config based on available network interfaces.
        Prioritizes an active (UP) non-loopback interface for Default Network Interface, IP, and MAC.
        Sets default port to 22 (SSH) and protocol to 'tcp'.
        """
        try:
            # Step 1: Collect interface data
            interfaces = netifaces.interfaces()
            self.Main_Config["List of Network Interfaces (Names)"] = interfaces
            self.Main_Config["List of Network Interfaces (MAC Addresses)"] = []
            self.Main_Config["List of Network Interfaces (IPv4 Addresses)"] = []
            self.Main_Config["List of Network Interfaces (IPv6 Addresses)"] = []
            self.Main_Config["List of Network Interfaces (Status)"] = []
    
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
                    ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'N/A')
    
                    # Get first global or unique local IPv6 (ignore link-local fe80::)
                    ipv6_list = addrs.get(netifaces.AF_INET6, [])
                    ipv6 = "N/A"
                    for addr in ipv6_list:
                        ip6 = addr.get('addr', '')
                        if ip6 and not ip6.startswith("fe80"):  # Skip link-local
                            ipv6 = ip6.split('%')[0]  # Remove zone index
                            break
    
                    status = 'UP' if psutil.net_if_stats().get(iface, None) and psutil.net_if_stats()[iface].isup else 'DOWN'
    
                    self.Main_Config["List of Network Interfaces (MAC Addresses)"].append(mac)
                    self.Main_Config["List of Network Interfaces (IPv4 Addresses)"].append(ipv4)
                    self.Main_Config["List of Network Interfaces (IPv6 Addresses)"].append(ipv6)
                    self.Main_Config["List of Network Interfaces (Status)"].append(status)
    
                except Exception as e:
                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error reading interface {iface}: {e}", message_type="ERROR")
    
            # Step 2: Select default interface (prefer UP, non-loopback with valid IPv4)
            default_interface = None
            default_ip = None
            default_mac = None
            for idx, iface in enumerate(self.Main_Config["List of Network Interfaces (Names)"]):
                if (self.Main_Config["List of Network Interfaces (Status)"][idx] == "UP" and
                    iface != "lo" and
                    self.Main_Config["List of Network Interfaces (IPv4 Addresses)"][idx] != "N/A" and
                    not self.Main_Config["List of Network Interfaces (IPv4 Addresses)"][idx].startswith("127.")):
                    default_interface = iface
                    default_ip = self.Main_Config["List of Network Interfaces (IPv4 Addresses)"][idx]
                    default_mac = self.Main_Config["List of Network Interfaces (MAC Addresses)"][idx]
                    break
    
            # If no suitable interface found, fallback to first UP interface or first interface
            if not default_interface:
                for idx, iface in enumerate(self.Main_Config["List of Network Interfaces (Names)"]):
                    if self.Main_Config["List of Network Interfaces (Status)"][idx] == "UP":
                        default_interface = iface
                        default_ip = self.Main_Config["List of Network Interfaces (IPv4 Addresses)"][idx]
                        default_mac = self.Main_Config["List of Network Interfaces (MAC Addresses)"][idx]
                        break
                else:
                    # If no UP interface, use first interface
                    if interfaces:
                        default_interface = interfaces[0]
                        default_ip = self.Main_Config["List of Network Interfaces (IPv4 Addresses)"][0]
                        default_mac = self.Main_Config["List of Network Interfaces (MAC Addresses)"][0]
    
            # Step 3: Set defaults in Main_Config
            self.Main_Config["Default Network Interface"] = default_interface
            self.Main_Config["Default IP Address"] = default_ip
            self.Main_Config["Default MAC Address"] = default_mac
            self.Main_Config["Default Port"] = 22  # Common port for SSH
            self.Main_Config["Default Protocol"] = "tcp"  # Common protocol
            self.Main_Config["Spoofed IP Address"] = None
            self.Main_Config["Spoofed MAC Address"] = None
            self.Main_Config["Spoofed Port"] = None
            self.Main_Config["Spoofed Protocol"] = None
    
            # Log the updated configuration
            self.Logger_Functions.print_and_log("\n[\u001b[34m+\u001b[0m] Default Configuration Set:")
            self.Logger_Functions.print_and_log("=====================")
            for key, value in self.Main_Config.items():
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] \u001b[32m{key}\u001b[0m: {value}")
            self.Logger_Functions.print_and_log("=====================\n")
    
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error setting default configuration: \u001b[31m{e}\u001b[0m", message_type="ERROR")





    def monitor_config_changes(self, interval: int = 5):
        """
        Monitors network interface changes and updates Main_Config if needed.
        Runs in a background thread every `interval` seconds.
        Only applies updates if Auto Rotation is enabled.
        """
        def _monitor():
            while True:
                try:
                    # Skip if auto-rotation is disabled
                    if not self.Main_Config.get("Auto Rotation Enabled", False):
                        time.sleep(interval)
                        continue
    
                    # Take a snapshot of old config for comparison
                    old_config = copy.deepcopy(self.Main_Config)
    
                    # Refresh the config
                    self.set_default_config()
    
                    # Compare old vs new
                    if old_config != self.Main_Config:
                        self.Logger_Functions.print_and_log(
                            f"[\u001b[33m$\u001b[0m] Network configuration changed → Main_Config updated."
                        )
    
                except Exception as e:
                    self.Logger_Functions.print_and_log(
                        f"[\033[31m!\u001b[0m] Error while monitoring config: {e}",
                        message_type="ERROR"
                    )
                
                time.sleep(interval)
    
        # Start monitoring in background
        t = threading.Thread(target=_monitor, daemon=True)
        t.start()
         
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Network Configuration -------------------- #    
    
    def random_mac(self):
        return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))




    def spoof_random_mac(self, iface=None):
        iface = iface or self.Main_Config["Default Network Interface"]
        mac = self.random_mac()
        self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Spoofing random MAC: {mac}")
        self.change_mac(iface, mac)




    def spoof_random_ip(self, iface=None, base="192.168.1."):
        iface = iface or self.Main_Config["Default Network Interface"]
        ip = base + str(random.randint(2, 254))
        self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Spoofing random IP: {ip}")
        self.change_ip(iface, ip)  
 



    def change_mac(self, iface=None, new_mac=None, reverse=False):
        import subprocess
        iface = iface or self.Main_Config["Default Network Interface"]
        if reverse:
            mac = self.Main_Config.get("Default MAC Address")
        else:
            mac = new_mac or self.Main_Config.get("Spoofed MAC Address")

        if not iface or not mac:
            self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] Interface or MAC address not provided.")
            return

        subprocess.call(["sudo", "ifconfig", iface, "down"])
        subprocess.call(["sudo", "ifconfig", iface, "hw", "ether", mac])
        subprocess.call(["sudo", "ifconfig", iface, "up"])




    def change_ip(self, iface=None, new_ip=None, reverse=False):
        import subprocess
        iface = iface or self.Main_Config["Default Network Interface"]
        if reverse:
            ip = self.Main_Config.get("Default IP Address")
        else:
            ip = new_ip or self.Main_Config.get("Spoofed IP Address")

        if not iface or not ip:
            self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] Interface or IP address not provided.")
            return

        subprocess.call(["sudo", "ifconfig", iface, ip])  
   



    def set_static_ip(self, iface, ip, netmask, gateway):
        import subprocess
        subprocess.call(["sudo", "ifconfig", iface, ip, "netmask", netmask])
        subprocess.call(["sudo", "route", "add", "default", "gw", gateway, iface])
 



    def auto_rotate_mac_ip(self, interval=None):
        interval = interval or self.Main_Config.get("Rotation Interval", 300)
        self.Main_Config["Auto Rotation Enabled"] = True
    
        def rotate():
            while self.Main_Config.get("Auto Rotation Enabled"):
                self.spoof_random_mac()
                self.spoof_random_ip()
                self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] MAC/IP rotated. Next in {interval} sec...")
                time.sleep(interval)
    
        threading.Thread(target=rotate, daemon=True).start()  
  



    def stop_auto_rotate(self):
        self.Main_Config["Auto Rotation Enabled"] = False
        self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] Auto MAC/IP rotation stopped.")   
  



    def reset_defaults(self):
        self.change_mac(reverse=True)
        self.change_ip(reverse=True) 
 



    def set_dns(self, dns_list=None):
        dns_list = dns_list or ["8.8.8.8", "1.1.1.1"]
        try:
            with open("/etc/resolv.conf", "w") as f:
                for dns in dns_list:
                    f.write(f"nameserver {dns}\n")
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] DNS servers set to: {', '.join(dns_list)}")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Failed to set DNS: {e}")   
     
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Wi-Fi Management -------------------- #
   
    def scan_wifi(self, iface):
        import subprocess
        subprocess.call(["sudo", "iwlist", iface, "scan"])    
   



    def parse_wifi_scan(self, iface=None):
        iface = iface or self.Main_Config["Default Network Interface"]
        try:
            output = subprocess.check_output(["sudo", "iwlist", iface, "scan"]).decode()
            networks = re.findall(
                r"Cell \d+ - Address: (.*?)\n.*?ESSID:\"(.*?)\".*?Signal level=(.*?) dBm.*?Channel:(\d+)",
                output,
                re.DOTALL
            )
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Found {len(networks)} networks on {iface}")
            for bssid, ssid, signal, channel in networks:
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] SSID: {ssid or '<Hidden>'}\n   BSSID: {bssid}\n   Signal: {signal} dBm\n   Channel: {channel}\n")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Failed to parse scan: {e}")   
  



    def connect_wifi(self, ssid, password, security=None):
        """
        Connect to a Wi-Fi network using nmcli with support for WEP, WPA/WPA2.
    
        Args:
            ssid (str): SSID of the network.
            password (str): Wi-Fi password/key.
            security (str): Optional; specify 'wep', 'wpa', or leave None to auto-detect (future).
        """
        try:
            cmd = ["nmcli", "dev", "wifi", "connect", ssid, "password", password]
    
            if security and security.lower() == "wep":
                cmd += ["wep-key-type", "key"]  # or "phrase" if you're using a passphrase
    
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Connected to {ssid} successfully.")
            else:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Failed to connect to {ssid}:\n{result.stderr.strip()}")
    
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error connecting to Wi-Fi: {e}")   
 



    def reconnect_wifi(self, iface):
        import subprocess
        subprocess.call(["nmcli", "device", "disconnect", iface])
        subprocess.call(["nmcli", "device", "connect", iface]) 
 



    def save_wifi_profile(self, profile_name, ssid, password):
        self.Saved_WiFi_Profiles[profile_name] = {"ssid": ssid, "password": password}
        with open("Saved_WiFi_Profiles.json", "w") as f:
            json.dump(self.Saved_WiFi_Profiles, f, indent=4)
        self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Saved Wi-Fi profile '{profile_name}'")




    def load_wifi_profiles(self):
        try:
            with open("Saved_WiFi_Profiles.json", "r") as f:
                self.Saved_WiFi_Profiles = json.load(f)
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Loaded saved Wi-Fi profiles.")
        except FileNotFoundError:
            self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No saved Wi-Fi profiles found.")




    def connect_to_saved_profile(self, profile_name):
        profile = self.Saved_WiFi_Profiles.get(profile_name)
        if not profile:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Profile '{profile_name}' not found.")
            return
        self.connect_wifi(profile['ssid'], profile['password'])
 



    def suggest_best_channel(self, iface=None):
        iface = iface or self.Main_Config["Default Network Interface"]
        try:
            output = subprocess.check_output(["sudo", "iwlist", iface, "scan"]).decode()
            channels = re.findall(r"Channel:(\d+)", output)
            if not channels:
                self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No channels found.")
                return
            counts = {ch: channels.count(ch) for ch in set(channels)}
            least_used = min(counts.items(), key=lambda x: x[1])[0]
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Suggested Channel: {least_used} (Least Congested)")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Channel optimization failed: {e}") 
 



    def enhance_roaming(self, target_ssid):
        iface = self.Main_Config["Default Network Interface"]
        self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Roaming monitor started for SSID: {target_ssid}")

        def roam():
            best_signal = -100
            best_bssid = None
            while True:
                try:
                    output = subprocess.check_output(["sudo", "iwlist", iface, "scan"]).decode()
                    matches = re.findall(
                        r"Cell .*?Address: (.*?)\n.*?ESSID:\"(.*?)\".*?Signal level=(-?\d+) dBm",
                        output, re.DOTALL
                    )
                    for bssid, ssid, signal in matches:
                        signal = int(signal)
                        if ssid == target_ssid and signal > best_signal:
                            best_signal = signal
                            best_bssid = bssid

                    if best_bssid:
                        subprocess.call(["nmcli", "dev", "wifi", "connect", target_ssid])
                        self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Switched to strongest AP ({best_bssid}) with signal {best_signal} dBm")
                except Exception as e:
                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Roaming scan error: {e}")
                time.sleep(20)

        threading.Thread(target=roam, daemon=True).start() 
     



    def iw_dev_status(self):
        """
        Display low-level Wi-Fi interface status using 'iw dev'.
        """
        try:
            output = subprocess.check_output(["iw", "dev"]).decode()
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Wi-Fi Interface Status:\n" + output)
            interfaces = re.findall(r"Interface (\w+).*?type (\w+)", output, re.DOTALL)
            status_data = [{"Interface": iface, "Type": mode} for iface, mode in interfaces]
            self.SaveData({"WiFi_Interface_Status": status_data}, report_types=["csv", "txt"], metadata={"timestamp": time.time()})
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error retrieving Wi-Fi interface status: {e}")




    def enable_ap_mode(self, ssid: str, password: str, iface: str = None):
        """
        Enable Access Point (AP) mode using hostapd and dnsmasq.
        
        Args:
            ssid: SSID for the access point.
            password: Password for the access point (WPA2).
            iface: Interface to use (defaults to default interface).
        """
        try:
            iface = iface or self.Main_Config["Default Network Interface"]
            if not iface:
                self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No interface specified for AP mode.")
                return
            
            # Create hostapd configuration
            hostapd_conf = f"""
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
"""
            with open("/tmp/hostapd.conf", "w") as f:
                f.write(hostapd_conf)
            
            # Create dnsmasq configuration
            dnsmasq_conf = f"""
interface={iface}
dhcp-range=192.168.100.2,192.168.100.100,12h
"""
            with open("/tmp/dnsmasq.conf", "w") as f:
                f.write(dnsmasq_conf)
            
            # Stop conflicting services
            subprocess.call(["sudo", "systemctl", "stop", "NetworkManager"])
            
            # Configure interface
            subprocess.call(["sudo", "ifconfig", iface, "192.168.100.1", "netmask", "255.255.255.0"])
            
            # Start dnsmasq
            subprocess.call(["sudo", "dnsmasq", "-C", "/tmp/dnsmasq.conf"])
            
            # Start hostapd
            subprocess.Popen(["sudo", "hostapd", "/tmp/hostapd.conf"])
            
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Access Point enabled: SSID={ssid}, IP=192.168.100.1")
            self.SaveData(
                {"AP_Config": {"SSID": ssid, "Interface": iface, "IP": "192.168.100.1"}},
                report_types=["txt"],
                metadata={"timestamp": time.time()}
            )
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error enabling AP mode: {e}")




    def list_connected_clients_ap(self, iface: str = None):
        """
        List clients connected to the AP (requires AP mode enabled).
        
        Args:
            iface: Interface in AP mode (defaults to default interface).
        """
        try:
            iface = iface or self.Main_Config["Default Network Interface"]
            output = subprocess.check_output(["iw", "dev", iface, "station", "dump"]).decode()
            clients = re.findall(r"Station (\S+) \(on (\S+)\).*?signal:\s+(-?\d+) dBm", output, re.DOTALL)
            client_data = [{"MAC": mac, "Interface": iface, "Signal": signal} for mac, iface, signal in clients]
            if client_data:
                self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Connected AP Clients:")
                for client in client_data:
                    self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] MAC: {client['MAC']}, Signal: {client['Signal']} dBm")
                self.SaveData({"AP_Clients": client_data}, report_types=["csv", "txt"], metadata={"timestamp": time.time()})
            else:
                self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No clients connected to AP.")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error listing AP clients: {e}")
        
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Firewall and Security -------------------- #     
     
    def flush_iptables(self):
        try:
            subprocess.call(["sudo", "iptables", "-F"])
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Flushed all IPTables rules.")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error flushing IPTables: {e}")
    



    def block_ip(self, ip):
        try:
            subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Blocked IP: {ip}")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error blocking IP: {e}")
   



    def unblock_ip(self, ip):
        try:
            subprocess.call(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Unblocked IP: {ip}")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error unblocking IP: {e}")
    



    def allow_outgoing_port(self, port, protocol="tcp"):
        try:
            subprocess.call(["sudo", "iptables", "-A", "OUTPUT", "-p", protocol, "--dport", str(port), "-j", "ACCEPT"])
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Allowed outgoing {protocol.upper()} port {port}")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error allowing port: {e}")
    



    def block_outgoing_port(self, port, protocol="tcp"):
        try:
            subprocess.call(["sudo", "iptables", "-A", "OUTPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"])
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Blocked outgoing {protocol.upper()} port {port}")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error blocking port: {e}")
    



    def list_iptables_rules(self):
        try:
            rules = subprocess.check_output(["sudo", "iptables", "-L", "-n", "-v"]).decode()
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] IPTables Rules:\n" + rules)
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error listing IPTables rules: {e}")
        
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Network Diagnostics and Monitoring -------------------- 
             
    def check_internet(self, host="8.8.8.8"):
        result = subprocess.call(["ping", "-c", "1", "-W", "1", host], stdout=subprocess.DEVNULL)
        if result == 0:
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Internet is reachable.")
            return True
        else:
            self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No internet connectivity.")
            return False     
     



    def ping_test(self, host="8.8.8.8"):
        import subprocess
        subprocess.call(["ping", "-c", "4", host])
  



    def run_speed_test(self):
        try:
            import speedtest  # lazy import so install step can run first
            st = speedtest.Speedtest()
            self.Logger_Functions.print_and_log("[+] Running speed test...")
            download = st.download() / 1_000_000
            upload = st.upload() / 1_000_000
            ping = st.results.ping
            self.Logger_Functions.print_and_log(
                f"[+] Download: {download:.2f} Mbps\n[+] Upload: {upload:.2f} Mbps\n[+] Ping: {ping:.2f} ms"
            )
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[!] Speed test failed: {e}")
    
    



    def monitor_connection(self, iface=None, reconnect_profile=None):
        iface = iface or self.Main_Config["Default Network Interface"]
        self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Monitoring connection on interface: {iface}")

        def monitor():
            while True:
                is_up = psutil.net_if_stats().get(iface, None)
                if is_up and not is_up.isup:
                    self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] {iface} disconnected. Reconnecting...")
                    if reconnect_profile:
                        self.connect_to_saved_profile(reconnect_profile)
                time.sleep(5)

        self.disconnect_monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.disconnect_monitor_thread.start()
   



    def GetNetworkData(self, PrintDetails: bool = False, save_to_file: bool = False) -> tuple:
        """
        Extended to gather IPv6 private/global info alongside IPv4.
        """
        try:
            if os.geteuid() != 0:
                self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] GetNetworkData requires root privileges for ARP requests.")
                return (None,) * 20  # extended tuple size for IPv6 fields
    
            if not isinstance(PrintDetails, bool) or not isinstance(save_to_file, bool):
                self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] Invalid input types for PrintDetails or save_to_file.")
                return (None,) * 20
    
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface == 'lo':
                    continue
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addresses and netifaces.AF_INET6 not in addresses:
                    continue
    
                # IPv4
                ipv4_info = addresses.get(netifaces.AF_INET, [{}])[0]
                ip_address = ipv4_info.get('addr')
                is_ipv4_private = False
                if ip_address:
                    try:
                        is_ipv4_private = ipaddress.IPv4Address(ip_address).is_private
                    except:
                        is_ipv4_private = False
    
                # IPv6
                ipv6_info = addresses.get(netifaces.AF_INET6, [])
                ipv6_address = None
                ipv6_prefix_len = None
                is_ipv6_private = False
                for addr in ipv6_info:
                    ip6 = addr.get('addr', '')
                    if ip6 and not ip6.startswith("fe80"):  # ignore link-local
                        ipv6_address = ip6.split('%')[0]  # remove zone index if present
                        ipv6_prefix_len = addr.get('netmask') or addr.get('prefixlen')
                        if not ipv6_prefix_len:
                            ipv6_prefix_len = 64  # common default
                        try:
                            ip6_obj = ipaddress.IPv6Address(ipv6_address)
                            # Check if IPv6 Unique Local Address (fc00::/7)
                            is_ipv6_private = ip6_obj.is_private
                        except Exception:
                            is_ipv6_private = False
                        break
    
                # Only process if either IPv4 private or IPv6 private is found
                if not (is_ipv4_private or is_ipv6_private):
                    continue
    
                # For IPv4 fields:
                if ip_address and is_ipv4_private:
                    private_IPv4 = ip_address
                    subnet_mask_str = ipv4_info.get('netmask', '255.255.255.0')
                    try:
                        subnet_mask = ipaddress.IPv4Address(subnet_mask_str)
                        subnet_cidr = sum(bin(int(x)).count('1') for x in subnet_mask_str.split('.'))
                        Network_AddressCiderIPv4 = ipaddress.IPv4Network(f"{ip_address}/{subnet_cidr}", strict=False)
                    except ValueError as e:
                        self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid subnet mask for {iface}: {e}")
                        continue
    
                    broadcast_address = Network_AddressCiderIPv4.broadcast_address
                    usable_hosts = list(Network_AddressCiderIPv4.hosts())
                    total_hosts = len(usable_hosts) + 2
                    usable_host_ip_range = f"{usable_hosts[0]} - {usable_hosts[-1]}" if usable_hosts else "N/A"
                    network_IPv4 = Network_AddressCiderIPv4.network_address
    
                else:
                    # No IPv4 or no private IPv4 - fill with Nones or placeholders
                    private_IPv4 = None
                    subnet_mask_str = None
                    subnet_cidr = None
                    Network_AddressCiderIPv4 = None
                    broadcast_address = None
                    usable_hosts = []
                    total_hosts = 0
                    usable_host_ip_range = None
                    network_IPv4 = None
    
                # For IPv6 fields:
                if ipv6_address and is_ipv6_private:
                    # We'll report prefix length as subnet mask equivalent
                    prefix_len = int(ipv6_prefix_len) if ipv6_prefix_len else 64
                    try:
                        Network_AddressCiderIPv6 = ipaddress.IPv6Network(f"{ipv6_address}/{prefix_len}", strict=False)
                        network_IPv6 = Network_AddressCiderIPv6.network_address
                        total_hosts_v6 = Network_AddressCiderIPv6.num_addresses
                    except Exception as e:
                        self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid IPv6 network for {iface}: {e}")
                        Network_AddressCiderIPv6 = None
                        network_IPv6 = None
                        total_hosts_v6 = 0
                else:
                    Network_AddressCiderIPv6 = None
                    network_IPv6 = None
                    total_hosts_v6 = 0
    
                mac_address = addresses.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
    
                # Default gateways (IPv4 and IPv6)
                gateways = netifaces.gateways()
                default_gateway_ip = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
                default_gateway_mac = "None"
    
                default_gateway_ipv6 = gateways.get('default', {}).get(netifaces.AF_INET6, [None])[0]
    
                if default_gateway_ip:
                    arp_request = ARP(pdst=default_gateway_ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request
                    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                    default_gateway_mac = answered_list[0][1].hwsrc if answered_list else "None"
    
                # Public IP retrieval (IPv4 only for now)
                public_ip = "None"
                if self.check_internet():
                    for service in ['ifconfig.me', 'api.ipify.org', 'ip.42.pl/raw']:
                        try:
                            public_IPv4 = subprocess.run(
                                ['curl', '-s', service],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                timeout=5
                            )
                            if public_IPv4.returncode == 0 and public_IPv4.stdout.strip():
                                public_ip = public_IPv4.stdout.strip()
                                break
                        except (subprocess.SubprocessError, TimeoutError) as e:
                            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Failed to fetch public IP from {service}: {e}")
                            continue
    
                # Store data in instance
                with self.config_lock:
                    self.NetworkIP_CiderIPv4 = Network_AddressCiderIPv4
                    self.NetworkIP = network_IPv4
                    self.SubnetCiderNotation = subnet_cidr
                    self.subnet_mask = subnet_mask_str
                    self.private_IPv4 = private_IPv4
                    self.NetworkInterface = iface
                    if self.Main_Config["Default MAC Address"] is None:
                        self.Main_Config["Default MAC Address"] = mac_address
    
                    # Store IPv6 info
                    self.NetworkIP_CiderIPv6 = Network_AddressCiderIPv6
                    self.NetworkIPv6 = network_IPv6
                    self.IPv6PrefixLength = prefix_len if ipv6_address else None
                    self.DefaultGatewayIPv6 = default_gateway_ipv6
    
                if PrintDetails:
                    with self.config_lock:
                        self.Logger_Functions.print_and_log(f"[\u001b[32m>\u001b[0m] Current network data for interface {iface}:")
                        if Network_AddressCiderIPv4:
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv4 Network address: {network_IPv4}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv4 Subnet CIDR: {subnet_cidr}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv4 Subnet mask: {subnet_mask_str}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv4 Broadcast Address: {broadcast_address}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Private IPv4: {private_IPv4}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Total IPv4 Hosts: {total_hosts}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Usable IPv4 Hosts: {len(usable_hosts)}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Usable IPv4 Range: {usable_host_ip_range}")
                        if Network_AddressCiderIPv6:
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv6 Network address: {network_IPv6}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] IPv6 Prefix Length: {prefix_len}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Total IPv6 Addresses: {total_hosts_v6}")
                            self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Private IPv6 Address: {ipv6_address}")
    
                        self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] MAC Address: {mac_address}")
                        self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Default Gateway IPv4: {default_gateway_ip or 'None'}")
                        self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Default Gateway MAC: {default_gateway_mac}")
                        self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Default Gateway IPv6: {default_gateway_ipv6 or 'None'}")
    
                if save_to_file:
                    NetworkData = {
                        "IPv4_Network": str(Network_AddressCiderIPv4) if Network_AddressCiderIPv4 else "None",
                        "IPv4_Subnet": subnet_mask_str or "None",
                        "IPv4_Broadcast": str(broadcast_address) if broadcast_address else "None",
                        "Private_IPv4": private_IPv4 or "None",
                        "Public_IPv4": public_ip,
                        "IPv4_Total_Hosts": total_hosts,
                        "IPv4_Usable_Hosts": len(usable_hosts),
                        "IPv4_Usable_Range": usable_host_ip_range or "None",
                        "IPv6_Network": str(Network_AddressCiderIPv6) if Network_AddressCiderIPv6 else "None",
                        "IPv6_Prefix_Length": prefix_len if ipv6_address else "None",
                        "Private_IPv6": ipv6_address or "None",
                        "IPv6_Total_Addresses": total_hosts_v6,
                        "Network_Interface": iface,
                        "MAC_Address": mac_address,
                        "Default_Gateway_IPv4": default_gateway_ip or "None",
                        "Default_Gateway_MAC": default_gateway_mac,
                        "Default_Gateway_IPv6": default_gateway_ipv6 or "None"
                    }
                    NetworkList = [NetworkData]
                    try:
                        self.Reporter.CSV_GenerateReport(Data=NetworkList)
                        self.Reporter.TXT_GenerateReport(Data=NetworkList)
                    except Exception as e:
                        self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Failed to generate reports: {e}")
    
                return (
                    Network_AddressCiderIPv4,
                    str(network_IPv4) if network_IPv4 else None,
                    subnet_cidr,
                    subnet_mask_str,
                    str(broadcast_address) if broadcast_address else None,
                    private_IPv4,
                    public_ip,
                    total_hosts,
                    len(usable_hosts),
                    usable_host_ip_range,
                    Network_AddressCiderIPv6,
                    network_IPv6,
                    prefix_len if ipv6_address else None,
                    ipv6_address,
                    total_hosts_v6,
                    iface,
                    mac_address,
                    default_gateway_ip or "None",
                    default_gateway_mac,
                    default_gateway_ipv6 or "None"
                )
    
            self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No valid network interface with private IPv4 or IPv6 found.")
            return (None,) * 20
    
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] An error occurred in GetNetworkData: {e}")
            return (None,) * 20   




    def view_arp_table(self):
        """
        Display the current ARP table entries.
        """
        try:
            output = subprocess.check_output(["arp", "-n"]).decode()
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] ARP Table Entries:\n" + output)
            arp_entries = []
            for line in output.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4:
                    arp_entries.append({
                        "IP": parts[0],
                        "MAC": parts[2],
                        "Interface": parts[-1]
                    })
            if arp_entries:
                self.SaveData({"ARP_Table": arp_entries}, report_types=["csv", "txt"], metadata={"timestamp": time.time()})
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error viewing ARP table: {e}")




    def flush_arp_cache(self):
        """
        Clear the ARP cache to remove outdated or suspicious entries.
        """
        try:
            subprocess.call(["sudo", "ip", "-s", "-s", "neigh", "flush", "all"])
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] ARP cache flushed successfully.")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error flushing ARP cache: {e}")   
     



    def log_arp_spoofing(self):
        """
        Monitor and log potential ARP spoofing by detecting MAC/IP conflicts.
        """
        try:
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Starting ARP spoofing monitor...")
            arp_table = {}
            
            def monitor_arp():
                while True:
                    try:
                        output = subprocess.check_output(["arp", "-n"]).decode()
                        current_table = {}
                        for line in output.splitlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 4:
                                ip, mac = parts[0], parts[2]
                                current_table[ip] = mac
                        
                        for ip, mac in current_table.items():
                            if ip in arp_table and arp_table[ip] != mac:
                                self.Logger_Functions.print_and_log(
                                    f"[\u001b[34m+\u001b[0m] ARP spoofing detected: IP {ip} changed from {arp_table[ip]} to {mac}",
                                    message_type="WARNING"
                                )
                                self.SaveData(
                                    {"ARP_Spoof_Detected": {"IP": ip, "Old_MAC": arp_table[ip], "New_MAC": mac}},
                                    report_types=["txt"],
                                    metadata={"timestamp": time.time()}
                                )
                        arp_table.update(current_table)
                        time.sleep(5)
                    except Exception as e:
                        self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] ARP monitor error: {e}")
            
            threading.Thread(target=monitor_arp, daemon=True).start()
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error starting ARP spoofing monitor: {e}")




    def compare_arp_tables(self, interval: int = 300):
        """
        Periodically compare ARP table snapshots to detect changes.
        
        Args:
            interval: Time interval between comparisons in seconds (default: 300).
        """
        try:
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Starting ARP table comparison every {interval} seconds...")
            previous_table = {}
            
            def get_arp_snapshot():
                output = subprocess.check_output(["arp", "-n"]).decode()
                snapshot = {}
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        snapshot[parts[0]] = parts[2]
                return snapshot
            
            def compare_snapshots():
                while True:
                    current_table = get_arp_snapshot()
                    changes = []
                    for ip, mac in current_table.items():
                        if ip in previous_table and previous_table[ip] != mac:
                            changes.append({"IP": ip, "Old_MAC": previous_table[ip], "New_MAC": mac})
                    if changes:
                        self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] ARP table changes detected:")
                        for change in changes:
                            self.Logger_Functions.print_and_log(
                                f"[\u001b[36m-\u001b[0m] IP {change['IP']}: {change['Old_MAC']} -> {change['New_MAC']}",
                                message_type="WARNING"
                            )
                        self.SaveData({"ARP_Changes": changes}, report_types=["csv", "txt"], metadata={"timestamp": time.time()})
                    previous_table.update(current_table)
                    time.sleep(interval)
            
            threading.Thread(target=compare_snapshots, daemon=True).start()
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error in ARP table comparison: {e}")
   
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Network Security -------------------- #   
     
    def basic_ssh_port_check(self, ip: str, port: int = 22, timeout: float = 1.0):
        """
        Check if SSH service is running on a specified IP and port.
        
        Args:
            ip: IP address to check.
            port: Port to check (default: 22).
            timeout: Timeout for the connection attempt in seconds.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] SSH service detected on {ip}:{port}")
                return True
            else:
                self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] No SSH service on {ip}:{port}")
                return False
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error checking SSH port on {ip}: {e}")
            return False




    def ssh_login_test(self, ip: str, username: str, password: str, port: int = 22):
        """
        Test SSH login credentials using paramiko.
        
        Args:
            ip: IP address of the SSH server.
            username: SSH username.
            password: SSH password.
            port: SSH port (default: 22).
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password, timeout=5)
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] SSH login successful for {username}@{ip}:{port}")
            client.close()
            return True
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] SSH login failed for {username}@{ip}:{port}: {e}")
            return False




    def configure_ssh(self, install: bool = False):
        """
        Install and configure an SSH server (OpenSSH) on the local machine.
        
        Args:
            install: If True, install OpenSSH server if not already installed.
        """
        try:
            if install:
                self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] Installing OpenSSH server...")
                subprocess.call(["sudo", "apt-get", "update"])
                subprocess.call(["sudo", "apt-get", "install", "-y", "openssh-server"])
            
            # Ensure SSH service is running
            subprocess.call(["sudo", "systemctl", "enable", "ssh"])
            subprocess.call(["sudo", "systemctl", "start", "ssh"])
            self.Logger_Functions.print_and_log("[\u001b[34m+\u001b[0m] SSH server configured and started.")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error configuring SSH server: {e}")




    def scan_lan_for_ssh(self, ip_range: str = None):
        """
        Scan the LAN for devices running SSH services.
        
        Args:
            ip_range: CIDR notation or range (e.g., '192.168.1.0/24'). Uses current network if None.
        """
        try:
            if not ip_range:
                if self.NetworkIP_CiderIPv4:
                    ip_range = str(self.NetworkIP_CiderIPv4)
                else:
                    self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No network range provided and no default network found.")
                    return
            
            ip_network = ipaddress.ip_network(ip_range, strict=False)
            ssh_hosts = []
            self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Scanning {ip_range} for SSH services...")
            for ip in ip_network.hosts():
                if self.basic_ssh_port_check(str(ip)):
                    ssh_hosts.append(str(ip))
            
            if ssh_hosts:
                self.SaveData({"SSH_Hosts": ssh_hosts}, report_types=["csv", "txt"], metadata={"network": ip_range})
                self.Logger_Functions.print_and_log(f"[\u001b[34m+\u001b[0m] Found SSH services on: {', '.join(ssh_hosts)}")
            else:
                self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No SSH services found.")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error scanning LAN for SSH: {e}")
      
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Wireless Mode Management -------------------- #    
        
    def enable_monitor_mode(self, iface):
        import subprocess
        subprocess.call(["sudo", "airmon-ng", "start", iface])




    def disable_monitor_mode(self, iface):
        import subprocess
        subprocess.call(["sudo", "airmon-ng", "stop", iface])




    def set_channel(self, iface, channel):
        import subprocess
        subprocess.call(["sudo", "iwconfig", iface, "channel", str(channel)])
        
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- DHCP Management -------------------- #  
 
    def renew_dhcp(self, iface):
        import subprocess
        subprocess.call(["sudo", "dhclient", "-r", iface])
        subprocess.call(["sudo", "dhclient", iface])
        
     
     
     
     
     
    
    
    
    
    
    
    
    
    
    
  
    # -------------------- Profile Switching -------------------- #  

    def switch_profile(self, profile_name):
        iface = self.Main_Config["Default Network Interface"]
        profile = self.Network_Profiles.get(profile_name)

        if iface is None:
            self.Logger_Functions.print_and_log("[\033[31m!\u001b[0m] No default interface selected.")
            return

        if profile:
            ip = profile["ip"]
            netmask = profile["netmask"]
            gateway = profile["gateway"]
            self.set_static_ip(iface, ip, netmask, gateway)
            self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Switched {iface} to profile: {profile_name}")
        else:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Profile '{profile_name}' not found.")
 
    




























