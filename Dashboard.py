import sys
from typing import Dict, Optional
from Wifi_NetworkManager import Wifi_Manager






network_logo = """
\033[92m


 /$$   /$$             /$$                                       /$$      
| $$$ | $$            | $$                                      | $$      
| $$$$| $$  /$$$$$$  /$$$$$$   /$$  /$$  /$$  /$$$$$$   /$$$$$$ | $$   /$$
| $$ $$ $$ /$$__  $$|_  $$_/  | $$ | $$ | $$ /$$__  $$ /$$__  $$| $$  /$$/
| $$  $$$$| $$$$$$$$  | $$    | $$ | $$ | $$| $$  \ $$| $$  \__/| $$$$$$/ 
| $$\  $$$| $$_____/  | $$ /$$| $$ | $$ | $$| $$  | $$| $$      | $$_  $$ 
| $$ \  $$|  $$$$$$$  |  $$$$/|  $$$$$/$$$$/|  $$$$$$/| $$      | $$ \  $$
|__/  \__/ \_______/   \___/   \_____/\___/  \______/ |__/      |__/  \__/
                                                                          
                                                                          
                                                                          
 /$$      /$$                                                             
| $$$    /$$$                                                             
| $$$$  /$$$$  /$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  
| $$ $$/$$ $$ |____  $$| $$__  $$ |____  $$ /$$__  $$ /$$__  $$ /$$__  $$ 
| $$  $$$| $$  /$$$$$$$| $$  \ $$  /$$$$$$$| $$  \ $$| $$$$$$$$| $$  \__/ 
| $$\  $ | $$ /$$__  $$| $$  | $$ /$$__  $$| $$  | $$| $$_____/| $$       
| $$ \/  | $$|  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$       
|__/     |__/ \_______/|__/  |__/ \_______/ \____  $$ \_______/|__/       
                                            /$$  \ $$                     
                                           |  $$$$$$/                     
                                            \______/                      
                                            
                                        
\u001b[0m   
"""




class WifiFunctionsMenu(Wifi_Manager):
    """
    Main interface for managing and interacting with Wi-Fi and network functions.
    This class inherits from Wifi_Manager and provides a menu-driven dashboard
    for the user to execute network management functions.
    """














    def __init__(self):
        """
        Initializes the menu and the parent class.
        Defines the main menu options, including direct function calls and
        category submenus.
        """
        super().__init__()
        # The main_menu dictionary links user-friendly names to class methods

       
        
        self.main_menu = {
            "View Categories": lambda: self.view_categories(function_key="menu"),
            "View Configuration": self.view_config,
            "Interface Management": lambda: self.view_categories(function_key="Interface Management"),
            "Network Configuration": lambda: self.view_categories(function_key="Network Configuration"),
            "Wi-Fi Management": lambda: self.view_categories(function_key="Wi-Fi Management"),
            "Firewall and Security": lambda: self.view_categories(function_key="Firewall and Security"),
            "Network Diagnostics and Monitoring": lambda: self.view_categories(function_key="Network Diagnostics and Monitoring"),
            "Network Security": lambda: self.view_categories(function_key="Network Security"),
            "Wireless Mode Management": lambda: self.view_categories(function_key="Wireless Mode Management"),
            "DHCP Management": lambda: self.view_categories(function_key="DHCP Management"),
            "Profile Switching": lambda: self.view_categories(function_key="Profile Switching"),
            "Help": self.help_options,
            "Exit": lambda: sys.exit(0)
        }














    def categorize_wifi_functions(self) -> Dict:
        """
        Categorizes the methods of the Wifi_Manager class into dictionaries
        based on their functionality.
        """
        categories = {
            "Interface Management": {
                "list_interfaces": "Lists all network interfaces, their MAC addresses, IPv4/IPv6 addresses, and status (UP/DOWN).",
                "auto_select_interface": "Automatically selects a default network interface based on its status and non-loopback IP address.",
                "enable_interface": "Activates a specified network interface using ifconfig.",
                "disable_interface": "Deactivates a specified network interface using ifconfig.",
                "show_interface_stats": "Displays network interface statistics (e.g., bytes sent/received, packets, errors) using psutil.",
                "get_interface_addresses": "Retrieves MAC, IPv4, IPv6 addresses, and status for a specific interface."
            },
            "Network Configuration": {
                "spoof_random_mac": "Spoofs a random MAC address on a specified interface.",
                "spoof_random_ip": "Assigns a random IP address (within a specified base, e.g., 192.168.1.x) to an interface.",
                "change_mac": "Changes the MAC address of an interface, with an option to revert to the default MAC.",
                "change_ip": "Changes the IP address of an interface, with an option to revert to the default IP.",
                "set_static_ip": "Configures a static IP address, netmask, and gateway for an interface.",
                "auto_rotate_mac_ip": "Periodically rotates MAC and IP addresses on a specified interval.",
                "stop_auto_rotate": "Stops the automatic rotation of MAC and IP addresses.",
                "reset_defaults": "Reverts the interface to its default MAC and IP addresses.",
                "set_dns": "Configures custom DNS servers by modifying /etc/resolv.conf."
            },
            "Wi-Fi Management": {
                "scan_wifi": "Scans for available Wi-Fi networks using iwlist.",
                "parse_wifi_scan": "Parses the output of a Wi-Fi scan to extract SSID, BSSID, signal strength, and channel.",
                "connect_wifi": "Connects to a Wi-Fi network using nmcli, supporting WEP or WPA/WPA2 security.",
                "reconnect_wifi": "Disconnects and reconnects a specified interface using nmcli.",
                "save_wifi_profile": "Saves a Wi-Fi profile (SSID and password) to a JSON file.",
                "load_wifi_profiles": "Loads saved Wi-Fi profiles from a JSON file.",
                "connect_to_saved_profile": "Connects to a Wi-Fi network using a saved profile.",
                "suggest_best_channel": "Analyzes Wi-Fi scan results to suggest the least congested channel.",
                "enhance_roaming": "Monitors and switches to the strongest access point for a given SSID.",
                "iw_dev_status": "Displays low-level Wi-Fi interface status using 'iw dev'.",
                "enable_ap_mode": "Enables Access Point mode using hostapd and dnsmasq with specified SSID and password.",
                "list_connected_clients_ap": "Lists clients connected to the access point (requires AP mode)."
            },
            "Firewall and Security": {
                "flush_iptables": "Clears all IPTables rules.",
                "block_ip": "Blocks incoming traffic from a specified IP address.",
                "unblock_ip": "Removes a block rule for a specified IP address.",
                "allow_outgoing_port": "Allows outgoing traffic on a specified port and protocol (e.g., TCP).",
                "block_outgoing_port": "Blocks outgoing traffic on a specified port and protocol.",
                "list_iptables_rules": "Displays the current IPTables rules."
            },
            "Network Diagnostics and Monitoring": {
                "check_internet": "Tests internet connectivity by pinging a specified host (default: 8.8.8.8).",
                "ping_test": "Performs a ping test to a specified host (default: 8.8.8.8) with 4 packets.",
                "run_speed_test": "Runs a speed test using the speedtest library to measure download, upload, and ping.",
                "monitor_connection": "Continuously monitors the status of an interface and reconnects to a saved Wi-Fi profile if disconnected.",
                "GetNetworkData": "Gathers detailed network information (IPv4/IPv6 addresses, subnet details, gateway, etc.) and optionally saves it to reports.",
                "view_network_parameters": "Lists and selects parameters from NetworkData and Main_Config dictionaries.",  # New function
                "view_arp_table": "Displays the current ARP table entries.",
                "flush_arp_cache": "Clears the ARP cache to remove outdated or suspicious entries.",
                "log_arp_spoofing": "Monitors and logs potential ARP spoofing by detecting MAC/IP conflicts.",
                "compare_arp_tables": "Periodically compares ARP table snapshots to detect changes."
            },
            "Network Security": {
                "basic_ssh_port_check": "Checks if an SSH service is running on a specified IP and port.",
                "ssh_login_test": "Tests SSH login credentials using paramiko.",
                "configure_ssh": "Installs and configures an OpenSSH server on the local machine.",
                "scan_lan_for_ssh": "Scans the LAN for devices running SSH services."
            },
            "Wireless Mode Management": {
                "enable_monitor_mode": "Enables monitor mode on a specified interface using airmon-ng.",
                "disable_monitor_mode": "Disables monitor mode on a specified interface using airmon-ng.",
                "set_channel": "Sets the Wi-Fi channel for a specified interface using iwconfig."
            },
            "DHCP Management": {
                "renew_dhcp": "Releases and renews the DHCP lease for a specified interface."
            },
            "Profile Switching": {
                "switch_profile": "Switches to a predefined network profile (e.g., 'Office' or 'Home') with specified IP, netmask, and gateway settings."
            }
        }
        return categories














    def select_network_parameter(self, param_type: str = None) -> Optional[str]:
        """
        Lists parameters from NetworkData and Main_Config dictionaries filtered by param_type and allows the user to select one.
        Returns the selected parameter value or None if no selection is made.
        
        Args:
            param_type (str): Type of parameter to filter (e.g., 'interface', 'ip', 'port', 'protocol', 'mac', 'netmask', 'gateway').
                              If None, shows all parameters.
        """
        try:
            valid_params = {
                "interface": ["Default Network Interface", "Network_Interface", "List of Network Interfaces (Names)"],
                "ip": ["Private_IPv4", "Public_IPv4", "Default_Gateway_IPv4", "Spoofed IP Address", "Default IP Address"],
                "port": ["Default Port", "Spoofed Port"],
                "protocol": ["Default Protocol", "Spoofed Protocol"],
                "mac": ["MAC_Address", "Default MAC Address", "Spoofed MAC Address"],
                "netmask": ["IPv4_Subnet"],
                "gateway": ["Default_Gateway_IPv4"]
            }
            
            self.Logger_Functions.print_and_log(f"\n[\u001b[34m+\u001b[0m] Available {param_type if param_type else 'Network'} Parameters:")
            self.Logger_Functions.print_and_log("==============================")
            
            # Filter parameters based on param_type
            parameters = []
            if param_type:
                parameters = valid_params.get(param_type, [])
            else:
                parameters = list(self.NetworkData.keys()) + list(self.Main_Config.keys())
            
            # Handle special case for interface lists
            selected_value = None
            if param_type == "interface" and "List of Network Interfaces (Names)" in parameters:
                interfaces = self.Main_Config.get("List of Network Interfaces (Names)", [])
                if interfaces:
                    self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Available Interfaces from List of Network Interfaces (Names):")
                    for idx, iface in enumerate(interfaces, 1):
                        self.Logger_Functions.print_and_log(f"[\033[33m{idx}\u001b[0m] \u001b[32m{iface}\u001b[0m")
                    choice = input(f"[\u001b[32m>\u001b[0m] Select interface (number, press Enter to select other parameters): ").strip()
                    if choice and choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                        selected_value = interfaces[int(choice) - 1]
                        self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Selected Interface: \u001b[36m{selected_value}\u001b[0m")
                        return selected_value
            
            # Display filtered parameters
            param_list = []
            for param in parameters:
                if param != "List of Network Interfaces (Names)":  # Handled above
                    value = self.NetworkData.get(param, self.Main_Config.get(param))
                    param_list.append((param, value))
            
            for idx, (param, value) in enumerate(param_list, 1):
                self.Logger_Functions.print_and_log(f"[\033[33m{idx}\u001b[0m] \u001b[32m{param}\u001b[0m: {value}")
            self.Logger_Functions.print_and_log("==============================")
            
            choice = input(f"[\u001b[32m>\u001b[0m] Select parameter (number, press Enter to return): ").strip()
            if not choice:
                return None
            
            if choice.isdigit():
                choice = int(choice)
                if 1 <= choice <= len(param_list):
                    selected_param = param_list[choice - 1][0]
                    selected_value = param_list[choice - 1][1]
                    self.Logger_Functions.print_and_log(f"[\u001b[32m*\u001b[0m] Selected Parameter: \u001b[36m{selected_param}\u001b[0m")
                    return selected_value
                else:
                    self.Logger_Functions.print_and_log(f"[\u001b[32m>\u001b[0m] Please choose an option within the range 1 - \u001b[32m{len(param_list)}\u001b[0m", message_type="WARNING")
            else:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid option: \u001b[31m{choice}\u001b[0m", message_type="WARNING")
            return None
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error selecting parameter: \u001b[31m{e}\u001b[0m", message_type="ERROR")
            return None














    def view_network_parameters(self) -> None:
        """
        Displays and allows selection of parameters from NetworkData and Main_Config.
        """
        param_value = self.select_network_parameter()
        if param_value:
            self.Logger_Functions.print_and_log(f"\n[\u001b[32m*\u001b[0m] Selected Value: \u001b[36m{param_value}\u001b[0m")














    def view_categories(self, function_key: str = 'menu') -> Optional[Dict]:
        # [Unchanged]
        categories = self.categorize_wifi_functions()
        
        if function_key == "menu":
            self.Logger_Functions.print_and_log("\n[\u001b[32m*\u001b[0m] Available Categories:")
            self.Logger_Functions.print_and_log("==============================")
            for idx, category in enumerate(categories.keys(), 1):
                self.Logger_Functions.print_and_log(f"[\033[33m{idx}\u001b[0m] \u001b[32m{category}\u001b[0m")
            self.Logger_Functions.print_and_log("==============================")
            sub_option = input(f"[\u001b[32m>\u001b[0m] Select category to \u001b[36mview functions\u001b[0m or (\u001b[31mpress Enter to return\u001b[0m): ").strip()
            if sub_option:
                self.handle_category_selection(categories, sub_option)
            return categories
        
        elif function_key in categories:
            try:
                self.Logger_Functions.print_and_log(f"\n[\u001b[34m+\u001b[0m] Functions in \u001b[32m{function_key}\u001b[0m:")
                self.print_submenu(categories[function_key])
                sub_option = input(f"[\u001b[32m>\u001b[0m] Select function to \u001b[36mview description\u001b[0m or (\u001b[31mpress Enter to return\u001b[0m): ").strip()
                if sub_option:
                    self.handle_submenu(categories[function_key], sub_option)
            except Exception as e:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error in category \033[31m{function_key}\u001b[0m: \u001b[31m{e}\u001b[0m", message_type="ERROR")
        else:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid category: \033[31m{function_key}\u001b[0m", message_type="WARNING")
        return None














    def handle_submenu(self, submenu: Dict, sub_option: str) -> None:
        """Handle function selection from a category and execute the function."""
        if sub_option.isdigit():
            sub_option = int(sub_option)
            if 1 <= sub_option <= len(submenu):
                sub_key = list(submenu.keys())[sub_option - 1]
                func_name = sub_key.strip("\u001b[32m").strip("\u001b[0m")  # Remove ANSI color codes
                self.Logger_Functions.print_and_log(f"\n[\u001b[32m*\u001b[0m] Function: \033[36m{sub_key}\u001b[0m")
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] Description: {submenu[sub_key]}")
                
                # Get the function from the class
                func = getattr(self, func_name, None)
                if func and callable(func):
                    try:
                        # Handle functions requiring parameters
                        if func_name in ["enable_interface", "disable_interface", "get_interface_addresses", "scan_wifi", "parse_wifi_scan", "reconnect_wifi", "enable_monitor_mode", "disable_monitor_mode", "renew_dhcp"]:
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter to select from config): ").strip()
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            func(iface)
                        elif func_name == "connect_wifi":
                            ssid = input("[\u001b[32m>\u001b[0m] Enter SSID: ").strip()
                            password = input("[\u001b[32m>\u001b[0m] Enter password: ").strip()
                            security = input("[\u001b[32m>\u001b[0m] Enter security type (wep/wpa, press Enter for auto): ").strip() or None
                            func(ssid, password, security)
                        elif func_name == "save_wifi_profile":
                            profile_name = input("[\u001b[32m>\u001b[0m] Enter profile name: ").strip()
                            ssid = input("[\u001b[32m>\u001b[0m] Enter SSID: ").strip()
                            password = input("[\u001b[32m>\u001b[0m] Enter password: ").strip()
                            func(profile_name, ssid, password)
                        elif func_name == "connect_to_saved_profile":
                            profile_name = input("[\u001b[32m>\u001b[0m] Enter profile name: ").strip()
                            func(profile_name)
                        elif func_name == "suggest_best_channel" or func_name == "list_connected_clients_ap":
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter for default or select from config): ").strip() or None
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            func(iface)
                        elif func_name == "enable_ap_mode":
                            ssid = input("[\u001b[32m>\u001b[0m] Enter SSID for AP: ").strip()
                            password = input("[\u001b[32m>\u001b[0m] Enter WPA2 password: ").strip()
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter for default or select from config): ").strip() or None
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            func(ssid, password, iface)
                        elif func_name == "block_ip" or func_name == "unblock_ip":
                            ip = input("[\u001b[32m>\u001b[0m] Enter IP address (press Enter to select from config): ").strip()
                            if not ip:
                                ip = self.select_network_parameter(param_type="ip")
                                if not ip:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid IP address selected", message_type="WARNING")
                                    return
                            func(ip)
                        elif func_name == "allow_outgoing_port" or func_name == "block_outgoing_port":
                            port = input("[\u001b[32m>\u001b[0m] Enter port number (press Enter to select from config): ").strip()
                            if not port:
                                port = self.select_network_parameter(param_type="port")
                                if not port:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid port selected", message_type="WARNING")
                                    return
                            port = int(port)
                            protocol = input("[\u001b[32m>\u001b[0m] Enter protocol (tcp/udp, press Enter for default or select from config): ").strip() or None
                            if not protocol:
                                protocol = self.select_network_parameter(param_type="protocol")
                                if not protocol:
                                    protocol = "tcp"
                            func(port, protocol)
                        elif func_name == "enhance_roaming":
                            ssid = input("[\u001b[32m>\u001b[0m] Enter target SSID: ").strip()
                            func(ssid)
                        elif func_name == "set_static_ip":
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter to select from config): ").strip()
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            ip = input("[\u001b[32m>\u001b[0m] Enter IP address (press Enter to select from config): ").strip()
                            if not ip:
                                ip = self.select_network_parameter(param_type="ip")
                                if not ip:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid IP address selected", message_type="WARNING")
                                    return
                            netmask = input("[\u001b[32m>\u001b[0m] Enter netmask (press Enter to select from config): ").strip()
                            if not netmask:
                                netmask = self.select_network_parameter(param_type="netmask")
                                if not netmask:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid netmask selected", message_type="WARNING")
                                    return
                            gateway = input("[\u001b[32m>\u001b[0m] Enter gateway (press Enter to select from config): ").strip()
                            if not gateway:
                                gateway = self.select_network_parameter(param_type="gateway")
                                if not gateway:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid gateway selected", message_type="WARNING")
                                    return
                            func(iface, ip, netmask, gateway)
                        elif func_name == "spoof_random_ip":
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter for default or select from config): ").strip() or None
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            base = input("[\u001b[32m>\u001b[0m] Enter base subnet (e.g., 192.168.1., press Enter for default): ").strip() or "192.168.1."
                            func(iface, base)
                        elif func_name == "change_mac":
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter for default or select from config): ").strip() or None
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            new_mac = input("[\u001b[32m>\u001b[0m] Enter new MAC address (press Enter for default or select from config): ").strip() or None
                            if not new_mac:
                                new_mac = self.select_network_parameter(param_type="mac")
                                if not new_mac:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid MAC address selected", message_type="WARNING")
                                    return
                            reverse = input("[\u001b[32m>\u001b[0m] Revert to default MAC? (y/n): ").strip().lower() == 'y'
                            func(iface, new_mac, reverse)
                        elif func_name == "change_ip":
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter for default or select from config): ").strip() or None
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            new_ip = input("[\u001b[32m>\u001b[0m] Enter new IP address (press Enter for default or select from config): ").strip() or None
                            if not new_ip:
                                new_ip = self.select_network_parameter(param_type="ip")
                                if not new_ip:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid IP address selected", message_type="WARNING")
                                    return
                            reverse = input("[\u001b[32m>\u001b[0m] Revert to default IP? (y/n): ").strip().lower() == 'y'
                            func(iface, new_ip, reverse)
                        elif func_name == "set_dns":
                            dns_list = input("[\u001b[32m>\u001b[0m] Enter DNS servers (comma-separated, e.g., 8.8.8.8,1.1.1.1): ").strip()
                            dns_list = dns_list.split(",") if dns_list else None
                            func(dns_list)
                        elif func_name == "auto_rotate_mac_ip":
                            interval = input("[\u001b[32m>\u001b[0m] Enter rotation interval in seconds (press Enter for default): ").strip()
                            interval = int(interval) if interval.isdigit() else None
                            func(interval)
                        elif func_name == "basic_ssh_port_check":
                            ip = input("[\u001b[32m>\u001b[0m] Enter IP address (press Enter to select from config): ").strip()
                            if not ip:
                                ip = self.select_network_parameter(param_type="ip")
                                if not ip:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid IP address selected", message_type="WARNING")
                                    return
                            port = input("[\u001b[32m>\u001b[0m] Enter port (press Enter to select from config or default 22): ").strip()
                            if not port:
                                port = self.select_network_parameter(param_type="port")
                                if not port:
                                    port = 22
                            port = int(port)
                            timeout = float(input("[\u001b[32m>\u001b[0m] Enter timeout in seconds (default 1.0): ").strip() or 1.0)
                            func(ip, port, timeout)
                        elif func_name == "ssh_login_test":
                            ip = input("[\u001b[32m>\u001b[0m] Enter IP address (press Enter to select from config): ").strip()
                            if not ip:
                                ip = self.select_network_parameter(param_type="ip")
                                if not ip:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid IP address selected", message_type="WARNING")
                                    return
                            username = input("[\u001b[32m>\u001b[0m] Enter username: ").strip()
                            password = input("[\u001b[32m>\u001b[0m] Enter password: ").strip()
                            port = input("[\u001b[32m>\u001b[0m] Enter port (press Enter to select from config or default 22): ").strip()
                            if not port:
                                port = self.select_network_parameter(param_type="port")
                                if not port:
                                    port = 22
                            port = int(port)
                            func(ip, username, password, port)
                        elif func_name == "scan_lan_for_ssh":
                            ip_range = input("[\u001b[32m>\u001b[0m] Enter IP range (e.g., 192.168.1.0/24, press Enter for default): ").strip() or None
                            func(ip_range)
                        elif func_name == "configure_ssh":
                            install = input("[\u001b[32m>\u001b[0m] Install OpenSSH server? (y/n): ").strip().lower() == 'y'
                            func(install)
                        elif func_name == "set_channel":
                            iface = input("[\u001b[32m>\u001b[0m] Enter interface name (e.g., wlan0, press Enter to select from config): ").strip()
                            if not iface:
                                iface = self.select_network_parameter(param_type="interface")
                                if not iface:
                                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] No valid interface selected", message_type="WARNING")
                                    return
                            channel = int(input("[\u001b[32m>\u001b[0m] Enter channel number: "))
                            func(iface, channel)
                        elif func_name == "switch_profile":
                            profile_name = input("[\u001b[32m>\u001b[0m] Enter profile name (e.g., Office): ").strip()
                            func(profile_name)
                        elif func_name == "GetNetworkData":
                            print_details = input("[\u001b[32m>\u001b[0m] Print details? (y/n): ").strip().lower() == 'y'
                            save_to_file = input("[\u001b[32m>\u001b[0m] Save to file? (y/n): ").strip().lower() == 'y'
                            func(print_details, save_to_file)
                        elif func_name == "compare_arp_tables":
                            interval = input("[\u001b[32m>\u001b[0m] Enter comparison interval in seconds (default 300): ").strip()
                            interval = int(interval) if interval.isdigit() else 300
                            func(interval)
                        elif func_name == "view_network_parameters":
                            func()
                        else:
                            # Execute functions that require no parameters
                            func()
                        
                    except Exception as e:
                        self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error executing \033[31m{sub_key}\u001b: \u001b[31m{e}\u001b[0m", message_type="ERROR")
                else:
                    self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Function \033[31m{sub_key}\u001b not found", message_type="ERROR")
            else:
                self.Logger_Functions.print_and_log(f"[\u001b[32m>\u001b[0m] Please choose an option within the range 1 - \033[31m{len(submenu)}\u001b", message_type="WARNING")
        else:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid option: \033[31m{sub_option}\u001b", message_type="WARNING")















    def view_config(self) -> None:
        """Display the current configuration from Main_Config."""
        try:
            self.Logger_Functions.print_and_log("\n[\u001b[34m+\u001b[0m] Current Configuration:")
            self.Logger_Functions.print_and_log("=====================")
            for key, value in self.Main_Config.items():
                self.Logger_Functions.print_and_log(f"[\u001b[36m-\u001b[0m] \u001b[32m{key}\u001b[0m: {value}")
            self.Logger_Functions.print_and_log("=====================\n")
        except Exception as e:
            self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Error displaying configuration: \u001b[31m{e}\u001b[0m", message_type="ERROR")
            
            













    def help_options(self) -> None:
        """Display help information for the Wi-Fi Functions Menu."""
        help_text = """
[$] Wi-Fi Functions Menu Help - This tool provides an interface to manage Wi-Fi and network functions.
========================================================================================================================
[\u001b[32m*\u001b[0m] \033[32mAvailable commands\u001b[0m:
[\u001b[36m-\u001b[0m] \033[33mView Categories\u001b[0m: View all available function categories.
[\u001b[36m-\u001b[0m] \033[33mView Configuration\u001b[0m: Show current network configuration settings.
[\u001b[36m-\u001b[0m] \033[33mInterface Management\u001b[0m: Manage network interfaces (list, enable/disable, etc.).
[\u001b[36m-\u001b[0m] \033[33mNetwork Configuration\u001b[0m: Change MAC/IP addresses, set static IPs, and manage DNS.
[\u001b[36m-\u001b[0m] \033[33mWi-Fi Management\u001b[0m: Scan, connect to, and manage Wi-Fi networks.
[\u001b[36m-\u001b[0m] \033[33mFirewall and Security\u001b[0m: Manage firewall rules (block/unblock IPs and ports).
[\u001b[36m-\u001b[0m] \033[33mNetwork Diagnostics and Monitoring\u001b[0m: Perform speed tests, check connectivity, and monitor ARP tables.
[\u001b[36m-\u001b[0m] \033[33mNetwork Security\u001b[0m: Test SSH logins and scan the local network for SSH services.
[\u001b[36m-\u001b[0m] \033[33mWireless Mode Management\u001b[0m: Enable/disable monitor mode and set the Wi-Fi channel.
[\u001b[36m-\u001b[0m] \033[33mDHCP Management\u001b[0m: Renew the DHCP lease for an interface.
[\u001b[36m-\u001b[0m] \033[33mProfile Switching\u001b[0m: Switch between predefined network profiles.
[\u001b[36m-\u001b[0m] \033[33mHelp\u001b[0m: Display this message.
[\u001b[36m-\u001b[0m] \033[33mExit\u001b[0m: Quit the program.
        """
        self.Logger_Functions.print_and_log(help_text)














    def print_submenu(self, submenu: Dict) -> None:
        """Print functions in a category."""
        self.Logger_Functions.print_and_log("==============================")
        for idx, sub_key in enumerate(submenu, 1):
            self.Logger_Functions.print_and_log(f"[\033[33m{idx}\u001b[0m] \u001b[36m{sub_key}\u001b[0m: {submenu[sub_key]}")
        self.Logger_Functions.print_and_log("==============================")            














    def handle_category_selection(self, categories: Dict, option: str) -> None:
        """Handle category selection from the View Categories menu."""
        if option.isdigit():
            option = int(option)
            if 1 <= option <= len(categories):
                category = list(categories.keys())[option - 1]
                self.view_categories(function_key=category)
            else:
                self.Logger_Functions.print_and_log(f"[\u001b[32m>\u001b[0m] Please choose an option within the range 1 - \u001b[32m{len(categories)}\u001b[0m", message_type="WARNING")
        else:
            option = option.capitalize()
            if option in categories:
                self.view_categories(function_key=option)
            else:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid category: \033[31m{option}\u001b[0m", message_type="WARNING")














    def view_func(self, option: str | int) -> None:
        """Display or execute menu options."""
        if isinstance(option, str) and option.lower() == "all":
            self.Logger_Functions.print_and_log("\n==============================")
            for index, view in enumerate(self.main_menu, 1):
                self.Logger_Functions.print_and_log(f"[\u001b[33m{index}\u001b[0m] \u001b[32m{view}\u001b[0m")
            self.Logger_Functions.print_and_log("==============================")
        
        elif isinstance(option, int) or (isinstance(option, str) and option.isdigit()):
            option = int(option)
            if 1 <= option <= len(self.main_menu):
                key = list(self.main_menu.keys())[option - 1]
                result = self.main_menu[key]()
                if isinstance(result, dict):  # For View Categories
                    self.view_categories(function_key="menu")
                else:
                    self.Logger_Functions.print_and_log(f"[\u001b[32m~\u001b[0m] Executing \u001b[32m{key}\u001b[0m")
            else:
                self.Logger_Functions.print_and_log(f"[\u001b[32m>\u001b[0m] Please choose an option within the range 1 - \u001b[32m{len(self.main_menu)}\u001b[0m", message_type="WARNING")
        
        elif isinstance(option, str):
            option = option.capitalize()
            if option in self.main_menu:
                result = self.main_menu[option]()
                if isinstance(result, dict):  # For View Categories
                    self.view_categories(function_key="menu")
                else:
                    self.Logger_Functions.print_and_log(f"[\u001b[32m~\u001b[0m] Executing \u001b[36m{option}\u001b[0m")
            else:
                self.Logger_Functions.print_and_log(f"[\033[31m!\u001b[0m] Invalid option: \u001b[31m{option}\u001b[0m", message_type="WARNING")














    def run(self):
        """Run the interactive menu."""
        while True:
            try:
                self.view_func("all")
                choice = input(f"[\u001b[32m>\u001b[0m] Enter option (number or name): ").strip()
                self.view_func(choice)
            except KeyboardInterrupt:
                self.Logger_Functions.print_and_log("\n[\033[31m!\u001b[0m] Exiting program...", message_type="INFO")
                sys.exit(0)
            except Exception as e:
                self.Logger_Functions.print_and_log(f"\n[\033[31m!\u001b[0m] Error: \u001b[31m{e}\u001b[0m", message_type="ERROR")
                
                
                
                
                
                
                
                
                
                
if __name__ == "__main__":
    menu = WifiFunctionsMenu()
    print(network_logo)
    menu.run_check()
    menu.run()