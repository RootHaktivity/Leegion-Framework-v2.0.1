"""
Enhanced Nmap Scanner module for Leegion Framework
Advanced network scanning with detailed reporting and multiple scan types

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
import threading
from core.base_module import BaseModule
from core.banner import print_module_header


class NmapScanner(BaseModule):
    """Enhanced Nmap scanner with multiple scan types and detailed reporting"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Nmap_Scanner")
        self.scan_results = []
        self.current_scan = None

    def run(self):
        """Main Nmap scanner interface"""
        print_module_header(
            "Nmap Scanner", "Advanced Network Discovery & Port Scanning"
        )

        # Check if nmap is available
        if not self._check_nmap_available():
            self.print_error("Nmap is not installed or not in PATH")
            self.print_info("Install with: sudo apt-get install nmap")
            return

        while True:
            self._display_scanner_menu()
            choice = self.get_user_input("Select scan type: ")

            if not choice:
                continue

            if choice == "1":
                self._quick_scan()
            elif choice == "2":
                self._full_tcp_scan()
            elif choice == "3":
                self._udp_scan()
            elif choice == "4":
                self._stealth_scan()
            elif choice == "5":
                self._version_detection_scan()
            elif choice == "6":
                self._os_detection_scan()
            elif choice == "7":
                self._vulnerability_scan()
            elif choice == "8":
                self._custom_scan()
            elif choice == "9":
                self._scan_network_range()
            elif choice == "10":
                self._view_scan_history()
            elif choice == "11":
                self._export_results()
            elif choice == "12":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_scanner_menu(self):
        """Display scanner menu options"""
        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'NMAP SCANNER MENU'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print("\033[96m 1.\033[0m Quick Scan (Top 1000 ports)")
        print("\033[96m 2.\033[0m Full TCP Scan (All ports)")
        print("\033[96m 3.\033[0m UDP Scan (Top UDP ports)")
        print("\033[96m 4.\033[0m Stealth Scan (SYN scan)")
        print("\033[96m 5.\033[0m Version Detection Scan")
        print("\033[96m 6.\033[0m OS Detection Scan")
        print("\033[96m 7.\033[0m Vulnerability Scan (NSE scripts)")
        print("\033[96m 8.\033[0m Custom Scan (Manual arguments)")
        print("\033[96m 9.\033[0m Network Range Scan")
        print("\033[96m10.\033[0m View Scan History")
        print("\033[96m11.\033[0m Export Results")
        print("\033[96m12.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")

    def _check_nmap_available(self) -> bool:
        """Check if nmap is available on the system"""
        try:
            result = subprocess.run(
                ["nmap", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _quick_scan(self):
        """Perform quick scan on top 1000 ports"""
        print(f"\n\033[96m📚 WHAT IS A QUICK NETWORK SCAN?\033[0m")
        print("A quick scan rapidly identifies open ports and running services")
        print("on a target system using Nmap's top 1000 most common ports.")
        print(f"\n\033[93m💡 WHAT YOU'LL DISCOVER:\033[0m")
        print("• Port 22 (SSH) - Remote terminal access")
        print("• Port 80/443 (HTTP/HTTPS) - Web servers and applications")
        print("• Port 21 (FTP) - File transfer services")
        print("• Port 25 (SMTP) - Email servers")
        print("• Port 3389 (RDP) - Windows remote desktop")
        print("• Port 445 (SMB) - Windows file sharing")
        print(f"\n\033[93m🎯 WHEN TO USE QUICK SCANS:\033[0m")
        print("• CTF competitions: Fast initial reconnaissance")
        print("• Time-constrained pentests: Rapid service discovery")
        print("• Network inventory: Quick asset identification")
        print("• Bug bounty: Initial target assessment")
        print(f"\n\033[96m⚡ SPEED vs ACCURACY:\033[0m")
        print(
            "Quick scans prioritize speed over stealth - use for time-sensitive scenarios"
        )

        target = self.get_user_input("\nEnter target IP or hostname: ", "general")
        if not target:
            return

        args = "-F -T4"  # Fast scan, aggressive timing
        self.print_info("Starting aggressive quick scan (top 1000 ports, high speed)")
        self.print_info("Scanning for: Web servers, SSH, FTP, email, database services")
        self._execute_nmap_scan(target, args, "Quick Scan")

    def _full_tcp_scan(self):
        """Perform full TCP port scan"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        self.print_warning("Full TCP scan may take a long time!")
        confirm = self.get_user_input("Continue? (y/N): ")
        if confirm.lower() != "y":
            return

        args = "-p- -T3"  # All ports, normal timing
        self._execute_nmap_scan(target, args, "Full TCP Scan")

    def _udp_scan(self):
        """Perform UDP port scan"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        self.print_warning("UDP scan requires root privileges and may be slow!")
        confirm = self.get_user_input("Continue? (y/N): ")
        if confirm.lower() != "y":
            return

        args = "-sU --top-ports 100"  # Top 100 UDP ports
        self._execute_nmap_scan(target, args, "UDP Scan")

    def _stealth_scan(self):
        """Perform stealth SYN scan"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        args = "-sS -T2"  # SYN stealth scan, polite timing
        self._execute_nmap_scan(target, args, "Stealth Scan")

    def _version_detection_scan(self):
        """Perform version detection scan"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        args = "-sV -T4"  # Version detection, aggressive timing
        self._execute_nmap_scan(target, args, "Version Detection")

    def _os_detection_scan(self):
        """Perform OS detection scan"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        self.print_warning("OS detection requires root privileges!")
        args = "-O -T4"  # OS detection, aggressive timing
        self._execute_nmap_scan(target, args, "OS Detection")

    def _vulnerability_scan(self):
        """Perform vulnerability scan using NSE scripts"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        # Select vulnerability categories
        print("\nVulnerability scan categories:")
        print("1. All vulnerability scripts")
        print("2. Default scripts + version detection")
        print("3. Web application vulnerabilities")
        print("4. SMB vulnerabilities")
        print("5. SSH vulnerabilities")

        category = self.get_user_input("Select category (1-5): ")

        script_args = {
            "1": "--script vuln",
            "2": "-sC -sV",
            "3": "--script http-*",
            "4": "--script smb-vuln-*",
            "5": "--script ssh-*",
        }

        args = script_args.get(category, "-sC -sV")
        self._execute_nmap_scan(target, args, "Vulnerability Scan")

    def _custom_scan(self):
        """Perform custom scan with user-defined arguments"""
        target = self.get_user_input("Enter target IP or hostname: ", "general")
        if not target:
            return

        self.print_info("Common Nmap arguments:")
        self.print_info("  -sS    : SYN stealth scan")
        self.print_info("  -sU    : UDP scan")
        self.print_info("  -sV    : Version detection")
        self.print_info("  -O     : OS detection")
        self.print_info("  -A     : Aggressive scan (OS, version, scripts)")
        self.print_info("  -p-    : Scan all ports")
        self.print_info("  -T4    : Aggressive timing")
        self.print_info("  --script <script> : Run NSE scripts")

        args = self.get_user_input("Enter custom Nmap arguments: ")
        if not args:
            return

        self._execute_nmap_scan(target, args, "Custom Scan")

    def _scan_network_range(self):
        """Scan a network range or CIDR block"""
        target = self.get_user_input(
            "Enter network range (e.g., 192.168.1.0/24): ", "general"
        )
        if not target:
            return

        # Host discovery first
        discovery_scan = self.get_user_input("Perform host discovery first? (Y/n): ")
        if discovery_scan.lower() != "n":
            self.print_info("Performing host discovery...")
            args = "-sn"  # Ping scan only
            self._execute_nmap_scan(target, args, "Host Discovery")

        # Port scan on discovered hosts
        scan_ports = self.get_user_input("Scan ports on discovered hosts? (Y/n): ")
        if scan_ports.lower() != "n":
            args = "-F -T4"  # Fast scan
            self._execute_nmap_scan(target, args, "Network Range Scan")

    def _execute_nmap_scan(self, target: str, args: str, scan_type: str):
        """Execute nmap scan with progress monitoring"""
        try:
            # Prepare command
            cmd = f"nmap {args} {target}".split()

            # Add output format options
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"nmap_{scan_type.lower().replace(' ', '_')}_{timestamp}"

            # Add XML output for parsing
            cmd.extend(["-oX", f"/tmp/{output_file}.xml"])
            cmd.extend(["-oN", f"/tmp/{output_file}.txt"])

            self.print_info(f"Starting {scan_type} on {target}")
            self.print_info(f"Command: {' '.join(cmd)}")

            start_time = time.time()
            self.logger.log_scan_start(scan_type, target)

            # Execute scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                universal_newlines=True,
            )

            # Monitor output
            output_lines = []
            for line in process.stdout:
                line = line.strip()
                if line:
                    print(f"\033[94m[Nmap]\033[0m {line}")
                    output_lines.append(line)

            # Wait for completion
            return_code = process.wait()
            scan_duration = time.time() - start_time

            if return_code == 0:
                self.print_success(f"{scan_type} completed successfully!")
                self.logger.log_scan_complete(scan_type, target, scan_duration)

                # Parse and store results
                self._parse_and_store_results(
                    f"/tmp/{output_file}.xml",
                    target,
                    scan_type,
                    scan_duration,
                    " ".join(cmd),
                )

            else:
                self.print_error(f"{scan_type} failed with return code: {return_code}")

        except Exception as e:
            self.print_error(f"Scan execution failed: {e}")
            self.logger.error(f"Nmap scan error: {e}")

    def _parse_and_store_results(
        self, xml_file: str, target: str, scan_type: str, duration: float, command: str
    ):
        """Parse XML results and store them"""
        try:
            # Parse XML results
            tree = ET.parse(xml_file)
            root = tree.getroot()

            scan_result = {
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "scan_type": scan_type,
                "duration": duration,
                "command": command,
                "hosts": [],
            }

            # Parse host information
            for host in root.findall("host"):
                host_info = self._parse_host_info(host)
                if host_info:
                    scan_result["hosts"].append(host_info)

            # Store results
            self.scan_results.append(scan_result)
            self.add_result(scan_result)

            # Display summary
            self._display_scan_summary(scan_result)

        except Exception as e:
            self.print_error(f"Failed to parse results: {e}")
            self.logger.error(f"XML parsing error: {e}")

    def _parse_host_info(self, host_element) -> Optional[Dict[str, Any]]:
        """Parse individual host information from XML"""
        try:
            host_info = {
                "addresses": [],
                "hostnames": [],
                "status": "unknown",
                "ports": [],
                "os": {},
                "scripts": [],
            }

            # Parse addresses
            for addr in host_element.findall("address"):
                host_info["addresses"].append(
                    {"addr": addr.get("addr"), "addrtype": addr.get("addrtype")}
                )

            # Parse hostnames
            hostnames = host_element.find("hostnames")
            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    host_info["hostnames"].append(
                        {"name": hostname.get("name"), "type": hostname.get("type")}
                    )

            # Parse status
            status = host_element.find("status")
            if status is not None:
                host_info["status"] = status.get("state")

            # Parse ports
            ports = host_element.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_info = self._parse_port_info(port)
                    if port_info:
                        host_info["ports"].append(port_info)

            # Parse OS information
            os_elem = host_element.find("os")
            if os_elem is not None:
                host_info["os"] = self._parse_os_info(os_elem)

            return host_info

        except Exception as e:
            self.logger.error(f"Host parsing error: {e}")
            return None

    def _parse_port_info(self, port_element) -> Optional[Dict[str, Any]]:
        """Parse port information from XML"""
        try:
            port_info = {
                "portid": port_element.get("portid"),
                "protocol": port_element.get("protocol"),
                "state": "unknown",
                "service": {},
            }

            # Parse state
            state = port_element.find("state")
            if state is not None:
                port_info["state"] = state.get("state")
                port_info["reason"] = state.get("reason")

            # Parse service
            service = port_element.find("service")
            if service is not None:
                port_info["service"] = {
                    "name": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", ""),
                    "tunnel": service.get("tunnel", ""),
                    "method": service.get("method", ""),
                }

            return port_info

        except Exception as e:
            self.logger.error(f"Port parsing error: {e}")
            return None

    def _parse_os_info(self, os_element) -> Dict[str, Any]:
        """Parse OS information from XML"""
        os_info = {"matches": [], "fingerprints": []}

        try:
            # Parse OS matches
            for osmatch in os_element.findall("osmatch"):
                os_info["matches"].append(
                    {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy"),
                        "line": osmatch.get("line"),
                    }
                )

            return os_info

        except Exception as e:
            self.logger.error(f"OS parsing error: {e}")
            return os_info

    def _display_scan_summary(self, scan_result: Dict[str, Any]):
        """Display summary of scan results"""
        print(f"\n\033[93m{'='*60}\033[0m")
        print(f"\033[93m{'SCAN SUMMARY'.center(60)}\033[0m")
        print(f"\033[93m{'='*60}\033[0m")

        print(f"\033[96mTarget:\033[0m {scan_result['target']}")
        print(f"\033[96mScan Type:\033[0m {scan_result['scan_type']}")
        print(f"\033[96mDuration:\033[0m {scan_result['duration']:.2f} seconds")
        print(f"\033[96mHosts Found:\033[0m {len(scan_result['hosts'])}")

        total_ports = sum(len(host["ports"]) for host in scan_result["hosts"])
        open_ports = sum(
            len([p for p in host["ports"] if p["state"] == "open"])
            for host in scan_result["hosts"]
        )

        print(f"\033[96mTotal Ports Scanned:\033[0m {total_ports}")
        print(f"\033[96mOpen Ports Found:\033[0m {open_ports}")

        # Display host details
        for i, host in enumerate(scan_result["hosts"], 1):
            print(f"\n\033[92mHost {i}:\033[0m")

            # Display IP addresses
            for addr in host["addresses"]:
                if addr["addrtype"] == "ipv4":
                    print(f"  \033[96mIP:\033[0m {addr['addr']}")

            # Display hostnames
            if host["hostnames"]:
                for hostname in host["hostnames"]:
                    print(f"  \033[96mHostname:\033[0m {hostname['name']}")

            print(f"  \033[96mStatus:\033[0m {host['status']}")

            # Display open ports
            open_ports = [p for p in host["ports"] if p["state"] == "open"]
            if open_ports:
                print(f"  \033[96mOpen Ports:\033[0m")
                for port in open_ports[:10]:  # Limit to first 10
                    service_info = port["service"]
                    service_name = service_info.get("name", "unknown")
                    product = service_info.get("product", "")
                    version = service_info.get("version", "")

                    port_desc = f"{port['portid']}/{port['protocol']}"
                    if product and version:
                        service_desc = f"{service_name} ({product} {version})"
                    elif product:
                        service_desc = f"{service_name} ({product})"
                    else:
                        service_desc = service_name

                    print(f"    {port_desc:15} {service_desc}")

                if len(open_ports) > 10:
                    print(f"    ... and {len(open_ports) - 10} more ports")

            # Display OS information if available
            if host["os"] and host["os"]["matches"]:
                best_match = host["os"]["matches"][0]
                print(
                    f"  \033[96mOS Guess:\033[0m {best_match['name']} ({best_match['accuracy']}% accuracy)"
                )

    def _view_scan_history(self):
        """View previous scan results"""
        if not self.scan_results:
            self.print_warning("No scan history available")
            return

        print(f"\n\033[93m{'SCAN HISTORY'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        for i, scan in enumerate(self.scan_results, 1):
            timestamp = scan["timestamp"][:19].replace("T", " ")
            print(f"\033[96m{i:2d}.\033[0m {scan['scan_type']} on {scan['target']}")
            print(
                f"     {timestamp} | Duration: {scan['duration']:.1f}s | Hosts: {len(scan['hosts'])}"
            )

        # Allow viewing detailed results
        choice = self.get_user_input(
            "\nView detailed results (enter scan number or 'q'): "
        )
        if choice and choice.isdigit():
            scan_idx = int(choice) - 1
            if 0 <= scan_idx < len(self.scan_results):
                self._display_scan_summary(self.scan_results[scan_idx])

    def _export_results(self):
        """Export scan results to various formats"""
        if not self.scan_results:
            self.print_warning("No scan results to export")
            return

        print("\nExport formats:")
        print("1. JSON")
        print("2. CSV")
        print("3. XML")
        print("4. Text Report")

        format_choice = self.get_user_input("Select format (1-4): ")

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get("output_dir", "./reports/output")

            if format_choice == "1":
                self._export_json(output_dir, timestamp)
            elif format_choice == "2":
                self._export_csv(output_dir, timestamp)
            elif format_choice == "3":
                self._export_xml(output_dir, timestamp)
            elif format_choice == "4":
                self._export_text_report(output_dir, timestamp)
            else:
                self.print_error("Invalid format selection")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_json(self, output_dir: str, timestamp: str):
        """Export results to JSON format"""
        import os

        os.makedirs(output_dir, exist_ok=True)

        filename = f"nmap_results_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            json.dump(self.scan_results, f, indent=2, default=str)

        self.print_success(f"Results exported to: {filepath}")

    def _export_csv(self, output_dir: str, timestamp: str):
        """Export results to CSV format"""
        import csv
        import os

        os.makedirs(output_dir, exist_ok=True)
        filename = f"nmap_results_{timestamp}.csv"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Timestamp",
                    "Target",
                    "Scan Type",
                    "Host IP",
                    "Status",
                    "Port",
                    "Protocol",
                    "State",
                    "Service",
                    "Product",
                    "Version",
                ]
            )

            for scan in self.scan_results:
                for host in scan["hosts"]:
                    host_ip = next(
                        (
                            addr["addr"]
                            for addr in host["addresses"]
                            if addr["addrtype"] == "ipv4"
                        ),
                        "unknown",
                    )

                    if host["ports"]:
                        for port in host["ports"]:
                            service = port["service"]
                            writer.writerow(
                                [
                                    scan["timestamp"],
                                    scan["target"],
                                    scan["scan_type"],
                                    host_ip,
                                    host["status"],
                                    port["portid"],
                                    port["protocol"],
                                    port["state"],
                                    service.get("name", ""),
                                    service.get("product", ""),
                                    service.get("version", ""),
                                ]
                            )
                    else:
                        writer.writerow(
                            [
                                scan["timestamp"],
                                scan["target"],
                                scan["scan_type"],
                                host_ip,
                                host["status"],
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                            ]
                        )

        self.print_success(f"Results exported to: {filepath}")

    def _export_xml(self, output_dir: str, timestamp: str):
        """Export results to XML format"""
        import xml.etree.ElementTree as ET
        import os

        os.makedirs(output_dir, exist_ok=True)
        filename = f"nmap_results_{timestamp}.xml"
        filepath = os.path.join(output_dir, filename)

        root = ET.Element("leegion_nmap_results")

        for scan in self.scan_results:
            scan_elem = ET.SubElement(root, "scan")
            scan_elem.set("timestamp", scan["timestamp"])
            scan_elem.set("target", scan["target"])
            scan_elem.set("type", scan["scan_type"])
            scan_elem.set("duration", str(scan["duration"]))

            for host in scan["hosts"]:
                host_elem = ET.SubElement(scan_elem, "host")
                host_elem.set("status", host["status"])

                # Add addresses
                for addr in host["addresses"]:
                    addr_elem = ET.SubElement(host_elem, "address")
                    addr_elem.set("addr", addr["addr"])
                    addr_elem.set("addrtype", addr["addrtype"])

                # Add ports
                ports_elem = ET.SubElement(host_elem, "ports")
                for port in host["ports"]:
                    port_elem = ET.SubElement(ports_elem, "port")
                    port_elem.set("portid", port["portid"])
                    port_elem.set("protocol", port["protocol"])
                    port_elem.set("state", port["state"])

                    # Add service info
                    service = port["service"]
                    if service:
                        service_elem = ET.SubElement(port_elem, "service")
                        for key, value in service.items():
                            if value:
                                service_elem.set(key, str(value))

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)

        self.print_success(f"Results exported to: {filepath}")

    def _export_text_report(self, output_dir: str, timestamp: str):
        """Export results as formatted text report"""
        import os

        os.makedirs(output_dir, exist_ok=True)
        filename = f"nmap_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write("LEEGION FRAMEWORK - NMAP SCAN REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Scans: {len(self.scan_results)}\n\n")

            for i, scan in enumerate(self.scan_results, 1):
                f.write(f"\nSCAN {i}: {scan['scan_type']}\n")
                f.write("-" * 40 + "\n")
                f.write(f"Target: {scan['target']}\n")
                f.write(f"Timestamp: {scan['timestamp']}\n")
                f.write(f"Duration: {scan['duration']:.2f} seconds\n")
                f.write(f"Command: {scan['command']}\n\n")

                for j, host in enumerate(scan["hosts"], 1):
                    f.write(f"  Host {j}:\n")

                    # Write IP addresses
                    for addr in host["addresses"]:
                        if addr["addrtype"] == "ipv4":
                            f.write(f"    IP: {addr['addr']}\n")

                    # Write hostnames
                    for hostname in host["hostnames"]:
                        f.write(f"    Hostname: {hostname['name']}\n")

                    f.write(f"    Status: {host['status']}\n")

                    # Write open ports
                    open_ports = [p for p in host["ports"] if p["state"] == "open"]
                    if open_ports:
                        f.write(f"    Open Ports ({len(open_ports)}):\n")
                        for port in open_ports:
                            service = port["service"]
                            port_line = f"      {port['portid']}/{port['protocol']}"
                            if service.get("name"):
                                port_line += f" - {service['name']}"
                            if service.get("product"):
                                port_line += f" ({service['product']}"
                                if service.get("version"):
                                    port_line += f" {service['version']}"
                                port_line += ")"
                            f.write(port_line + "\n")

                    # Write OS information
                    if host["os"] and host["os"]["matches"]:
                        best_match = host["os"]["matches"][0]
                        f.write(
                            f"    OS: {best_match['name']} ({best_match['accuracy']}%)\n"
                        )

                    f.write("\n")

        self.print_success(f"Report exported to: {filepath}")
