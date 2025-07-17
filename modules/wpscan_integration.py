"""
Enhanced WPScan Integration module for Leegion Framework
WordPress security assessment with comprehensive vulnerability detection

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import subprocess
import json
import re
import os
import csv
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
from core.base_module import BaseModule
from core.banner import print_module_header


class WPScanIntegration(BaseModule):
    """Enhanced WPScan integration for WordPress security assessment"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "WPScan_Integration")
        self.scan_results = []
        self.api_token = config.get("wpscan_api_token", "")

    def run(self):
        """Main WPScan interface"""
        print_module_header("WPScan Integration", "WordPress Security Assessment")

        # Check if WPScan is available
        if not self._check_wpscan_available():
            self.print_error("WPScan is not installed or not in PATH")
            self.print_info("Install with: gem install wpscan")
            self.print_info("Or: sudo apt-get install wpscan")
            return

        while True:
            self._display_wpscan_menu()
            choice = self.get_user_input("Select scan type: ")

            if not choice:
                continue

            if choice == "1":
                self._basic_wordpress_scan()
            elif choice == "2":
                self._enumerate_users()
            elif choice == "3":
                self._enumerate_plugins()
            elif choice == "4":
                self._enumerate_themes()
            elif choice == "5":
                self._vulnerability_scan()
            elif choice == "6":
                self._aggressive_scan()
            elif choice == "7":
                self._custom_scan()
            elif choice == "8":
                self._batch_scan()
            elif choice == "9":
                self._view_scan_results()
            elif choice == "10":
                self._export_results()
            elif choice == "11":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_wpscan_menu(self):
        """Display WPScan menu options"""
        api_status = "✓ Configured" if self.api_token else "✗ Not configured"

        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'WPSCAN INTEGRATION MENU'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print(f"\033[96mAPI Token Status:\033[0m {api_status}")
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m 1.\033[0m Basic WordPress Scan")
        print("\033[96m 2.\033[0m Enumerate Users")
        print("\033[96m 3.\033[0m Enumerate Plugins")
        print("\033[96m 4.\033[0m Enumerate Themes")
        print("\033[96m 5.\033[0m Vulnerability Database Scan")
        print("\033[96m 6.\033[0m Aggressive Scan (All enumerations)")
        print("\033[96m 7.\033[0m Custom Scan (Manual arguments)")
        print("\033[96m 8.\033[0m Batch Scan (Multiple URLs)")
        print("\033[96m 9.\033[0m View Scan Results")
        print("\033[96m10.\033[0m Export Results")
        print("\033[96m11.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")

        if not self.api_token:
            self.print_warning(
                "Consider configuring WPScan API token for vulnerability data"
            )
            self.print_info("Get token from: https://wpscan.com/api")

    def _check_wpscan_available(self) -> bool:
        """Check if WPScan is available on the system"""
        try:
            result = subprocess.run(
                ["wpscan", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _basic_wordpress_scan(self):
        """Perform basic WordPress scan"""
        print("\n\033[96m📚 WHAT IS WORDPRESS SCANNING?\033[0m")
        print(
            "WordPress scanning identifies security vulnerabilities in WordPress sites"
        )
        print("by checking for outdated plugins, themes, and core WordPress versions.")
        print("\n\033[93m💡 WHAT YOU'LL DISCOVER:\033[0m")
        print("• Outdated WordPress core version with known vulnerabilities")
        print("• Vulnerable plugins (contact forms, e-commerce, SEO tools)")
        print("• Insecure themes with backdoors or XSS vulnerabilities")
        print("• Exposed sensitive files (wp-config.php backups)")
        print("• User enumeration possibilities (author archives)")
        print("• Weak admin credentials through brute force")
        print("\n\033[93m🎯 REAL-WORLD SCENARIOS:\033[0m")
        print("• Bug bounty hunting: Finding vulnerable WordPress sites")
        print("• Security audits: Assessing client WordPress installations")
        print("• Red team exercises: Initial access through CMS vulnerabilities")
        print("• CTF competitions: WordPress-based web challenges")
        print(
            "\n\033[91m⚠️  IMPORTANT:\033[0m Only scan WordPress sites you own or have permission to test!"
        )

        target = self.get_user_input(
            "\nEnter WordPress URL (e.g., https://example.com): ", "url"
        )
        if not target:
            return

        args = ["--url", target, "--no-banner"]
        if self.api_token:
            args.extend(["--api-token", self.api_token])

        self.print_info("Starting comprehensive WordPress security scan...")
        self.print_info(
            "Checking: Core version, plugins, themes, users, configuration issues"
        )
        self._execute_wpscan(target, args, "Basic WordPress Scan")

    def _enumerate_users(self):
        """Enumerate WordPress users"""
        print("\n\033[96m📚 WHY ENUMERATE WORDPRESS USERS?\033[0m")
        print("User enumeration reveals WordPress usernames which can be used for:")
        print("• Password brute force attacks against wp-login.php")
        print("• Social engineering with discovered real names")
        print("• Privilege escalation (finding admin vs subscriber accounts)")
        print("\n\033[93m💡 COMMON FINDINGS:\033[0m")
        print("• admin - Default administrator account (high-value target)")
        print("• editor, author - Content management accounts")
        print("• Real names as usernames - Easier to guess passwords")
        print("• Service accounts - Often have weak or default passwords")

        target = self.get_user_input("\nEnter WordPress URL: ", "url")
        if not target:
            return

        print("\n\033[93m🎯 User enumeration techniques:\033[0m")
        print("1. Basic user enumeration (author archives)")
        print("2. Enumerate users with IDs 1-100 (common range)")
        print("3. Enumerate users with custom range")
        print("4. Aggressive user enumeration (all methods)")

        choice = self.get_user_input("Select option (1-4): ")

        args = ["--url", target, "--no-banner"]

        if choice == "1":
            args.extend(["--enumerate", "u"])
        elif choice == "2":
            args.extend(["--enumerate", "u1-100"])
        elif choice == "3":
            range_input = self.get_user_input("Enter user ID range (e.g., 1-50): ")
            if range_input:
                args.extend(["--enumerate", f"u{range_input}"])
            else:
                return
        elif choice == "4":
            args.extend(["--enumerate", "u", "--detection-mode", "aggressive"])
        else:
            self.print_error("Invalid option")
            return

        if self.api_token:
            args.extend(["--api-token", self.api_token])

        self._execute_wpscan(target, args, "User Enumeration")

    def _enumerate_plugins(self):
        """Enumerate WordPress plugins"""
        target = self.get_user_input("Enter WordPress URL: ", "url")
        if not target:
            return

        print("\nPlugin enumeration options:")
        print("1. Popular plugins only")
        print("2. Vulnerable plugins only")
        print("3. All plugins (may take time)")
        print("4. Aggressive detection")

        choice = self.get_user_input("Select option (1-4): ")

        args = ["--url", target, "--no-banner"]

        if choice == "1":
            args.extend(["--enumerate", "p"])
        elif choice == "2":
            args.extend(["--enumerate", "vp"])
        elif choice == "3":
            args.extend(["--enumerate", "ap"])
        elif choice == "4":
            args.extend(["--enumerate", "p", "--detection-mode", "aggressive"])
        else:
            self.print_error("Invalid option")
            return

        if self.api_token:
            args.extend(["--api-token", self.api_token])

        self._execute_wpscan(target, args, "Plugin Enumeration")

    def _enumerate_themes(self):
        """Enumerate WordPress themes"""
        target = self.get_user_input("Enter WordPress URL: ", "url")
        if not target:
            return

        print("\nTheme enumeration options:")
        print("1. Popular themes only")
        print("2. Vulnerable themes only")
        print("3. All themes")

        choice = self.get_user_input("Select option (1-3): ")

        args = ["--url", target, "--no-banner"]

        if choice == "1":
            args.extend(["--enumerate", "t"])
        elif choice == "2":
            args.extend(["--enumerate", "vt"])
        elif choice == "3":
            args.extend(["--enumerate", "at"])
        else:
            self.print_error("Invalid option")
            return

        if self.api_token:
            args.extend(["--api-token", self.api_token])

        self._execute_wpscan(target, args, "Theme Enumeration")

    def _vulnerability_scan(self):
        """Perform vulnerability database scan"""
        if not self.api_token:
            self.print_error("API token required for vulnerability scanning")
            self.print_info("Get token from: https://wpscan.com/api")
            return

        target = self.get_user_input("Enter WordPress URL: ", "url")
        if not target:
            return

        args = [
            "--url",
            target,
            "--no-banner",
            "--api-token",
            self.api_token,
            "--enumerate",
            "vp,vt,cb",  # Vulnerable plugins, themes, and config backups
            "--plugins-detection",
            "aggressive",
        ]

        self._execute_wpscan(target, args, "Vulnerability Scan")

    def _aggressive_scan(self):
        """Perform comprehensive aggressive scan"""
        target = self.get_user_input("Enter WordPress URL: ", "url")
        if not target:
            return

        self.print_warning("Aggressive scan may be detected by security systems!")
        confirm = self.get_user_input("Continue? (y/N): ")
        if confirm.lower() != "y":
            return

        args = [
            "--url",
            target,
            "--no-banner",
            "--enumerate",
            "ap,at,cb,dbe,u1-100",  # All plugins, themes, backups, DB exports, users
            "--detection-mode",
            "aggressive",
            "--plugins-detection",
            "aggressive",
            "--plugins-version-detection",
            "aggressive",
        ]

        if self.api_token:
            args.extend(["--api-token", self.api_token])

        self._execute_wpscan(target, args, "Aggressive Scan")

    def _custom_scan(self):
        """Perform custom scan with user-defined arguments"""
        target = self.get_user_input("Enter WordPress URL: ", "url")
        if not target:
            return

        self.print_info("Common WPScan arguments:")
        self.print_info("  --enumerate u        : Enumerate users")
        self.print_info("  --enumerate p        : Enumerate plugins")
        self.print_info("  --enumerate t        : Enumerate themes")
        self.print_info("  --enumerate vp       : Enumerate vulnerable plugins")
        self.print_info("  --enumerate cb       : Enumerate config backups")
        self.print_info("  --detection-mode aggressive : Aggressive detection")
        self.print_info("  --random-user-agent  : Use random user agents")
        self.print_info("  --force              : Force scan even if not WordPress")

        custom_args = self.get_user_input("Enter custom arguments (without --url): ")
        if not custom_args:
            return

        # Parse custom arguments
        args = ["--url", target, "--no-banner"]
        args.extend(custom_args.split())

        if self.api_token and "--api-token" not in custom_args:
            args.extend(["--api-token", self.api_token])

        self._execute_wpscan(target, args, "Custom Scan")

    def _batch_scan(self):
        """Scan multiple WordPress URLs"""
        self.print_info("Enter WordPress URLs (one per line, empty line to finish):")

        urls = []
        while True:
            url = input("URL: ").strip()
            if not url:
                break
            if self.validate_input(url, "url"):
                urls.append(url)

        if not urls:
            self.print_error("No valid URLs provided")
            return

        print(f"\nScan options for {len(urls)} URLs:")
        print("1. Basic scan for all")
        print("2. User enumeration for all")
        print("3. Plugin enumeration for all")
        print("4. Vulnerability scan for all")

        choice = self.get_user_input("Select scan type (1-4): ")

        scan_configs = {
            "1": (["--enumerate", "vp,vt"], "Basic Batch Scan"),
            "2": (["--enumerate", "u"], "User Enumeration Batch"),
            "3": (["--enumerate", "p"], "Plugin Enumeration Batch"),
            "4": (["--enumerate", "vp,vt,cb"], "Vulnerability Batch Scan"),
        }

        if choice not in scan_configs:
            self.print_error("Invalid choice")
            return

        enum_args, scan_type = scan_configs[choice]

        self.print_info(f"Starting {scan_type} for {len(urls)} URLs...")

        for i, url in enumerate(urls, 1):
            self.print_info(f"Scanning {i}/{len(urls)}: {url}")

            args = ["--url", url, "--no-banner"] + enum_args
            if self.api_token:
                args.extend(["--api-token", self.api_token])

            self._execute_wpscan(url, args, f"{scan_type} ({i}/{len(urls)})")

            # Small delay between scans to be respectful
            if i < len(urls):
                time.sleep(2)

    def _execute_wpscan(self, target: str, args: List[str], scan_type: str):
        """Execute WPScan with given arguments"""
        try:
            cmd = ["wpscan"] + args

            self.print_info(f"Starting {scan_type} on {target}")
            self.print_info(
                f"Command: {' '.join(cmd[:4])}..."
            )  # Show partial command for security

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

            # Capture output
            output_lines = []
            for line in process.stdout:
                line = line.strip()
                if line:
                    print(f"\033[95m[WPScan]\033[0m {line}")
                    output_lines.append(line)

            # Wait for completion
            return_code = process.wait()
            scan_duration = time.time() - start_time

            if return_code == 0:
                self.print_success(f"{scan_type} completed successfully!")
                self.logger.log_scan_complete(scan_type, target, scan_duration)

                # Parse and store results
                self._parse_and_store_results(
                    output_lines, target, scan_type, scan_duration, cmd
                )

            else:
                self.print_error(f"{scan_type} failed with return code: {return_code}")

        except Exception as e:
            self.print_error(f"Scan execution failed: {e}")
            self.logger.error(f"WPScan error: {e}")

    def _parse_and_store_results(
        self,
        output_lines: List[str],
        target: str,
        scan_type: str,
        duration: float,
        command: List[str],
    ):
        """Parse WPScan output and store results"""
        try:
            scan_result = {
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "scan_type": scan_type,
                "duration": duration,
                "command": " ".join(command[:4])
                + "...",  # Partial command for security
                "wordpress_info": {},
                "users": [],
                "plugins": [],
                "themes": [],
                "vulnerabilities": [],
                "interesting_entries": [],
                "summary": {},
            }

            # Parse output sections
            current_section = None

            for line in output_lines:
                line = line.strip()

                # Identify sections
                if "[+] WordPress version" in line:
                    version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", line)
                    if version_match:
                        scan_result["wordpress_info"]["version"] = version_match.group(
                            1
                        )

                elif "[+] WordPress theme in use:" in line:
                    theme_match = re.search(r"use: (.+?)(?:\s|$)", line)
                    if theme_match:
                        scan_result["wordpress_info"]["theme"] = theme_match.group(1)

                elif "[+] Enumerating users" in line:
                    current_section = "users"
                elif "[+] Enumerating plugins" in line:
                    current_section = "plugins"
                elif "[+] Enumerating themes" in line:
                    current_section = "themes"
                elif "[!] No WPVulnDB API Token given" in line:
                    scan_result["vulnerabilities"].append(
                        {
                            "type": "warning",
                            "message": "No API token provided for vulnerability data",
                        }
                    )

                # Parse user information
                elif current_section == "users" and line.startswith(" | "):
                    user_match = re.search(r"\|\s*(.+?)\s*\|", line)
                    if user_match:
                        scan_result["users"].append(
                            {"username": user_match.group(1).strip()}
                        )

                # Parse plugin information
                elif (
                    current_section == "plugins"
                    and " | " in line
                    and "Version:" in line
                ):
                    plugin_info = self._parse_plugin_line(line)
                    if plugin_info:
                        scan_result["plugins"].append(plugin_info)

                # Parse theme information
                elif (
                    current_section == "themes" and " | " in line and "Version:" in line
                ):
                    theme_info = self._parse_theme_line(line)
                    if theme_info:
                        scan_result["themes"].append(theme_info)

                # Parse vulnerabilities
                elif " vulnerabilities identified:" in line:
                    vuln_count = re.search(r"(\d+) vulnerabilities", line)
                    if vuln_count:
                        scan_result["summary"]["vulnerability_count"] = int(
                            vuln_count.group(1)
                        )

                # Parse interesting entries
                elif line.startswith("[+]") and (
                    "robots.txt" in line or "readme" in line
                ):
                    scan_result["interesting_entries"].append(line)

            # Store results
            self.scan_results.append(scan_result)
            self.add_result(scan_result)

            # Display summary
            self._display_scan_summary(scan_result)

        except Exception as e:
            self.print_error(f"Failed to parse results: {e}")
            self.logger.error(f"WPScan parsing error: {e}")

    def _parse_plugin_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse plugin information from output line"""
        try:
            # Example: " | Plugin Name | Version: 1.2.3 | "
            # "Location: /wp-content/plugins/plugin-name/"
            parts = [part.strip() for part in line.split("|") if part.strip()]

            if len(parts) >= 2:
                plugin_info = {"name": parts[1]}

                for part in parts[2:]:
                    if part.startswith("Version:"):
                        plugin_info["version"] = part.replace("Version:", "").strip()
                    elif part.startswith("Location:"):
                        plugin_info["location"] = part.replace("Location:", "").strip()

                return plugin_info
        except Exception:
            pass

        return None

    def _parse_theme_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse theme information from output line"""
        try:
            # Similar to plugin parsing
            parts = [part.strip() for part in line.split("|") if part.strip()]

            if len(parts) >= 2:
                theme_info = {"name": parts[1]}

                for part in parts[2:]:
                    if part.startswith("Version:"):
                        theme_info["version"] = part.replace("Version:", "").strip()
                    elif part.startswith("Location:"):
                        theme_info["location"] = part.replace("Location:", "").strip()

                return theme_info
        except Exception:
            pass

        return None

    def _display_scan_summary(self, scan_result: Dict[str, Any]):
        """Display summary of WPScan results"""
        print("\n\033[93m" + "=" * 60 + "\033[0m")
        print("\033[93m" + "WPSCAN SUMMARY".center(60) + "\033[0m")
        print("\033[93m" + "=" * 60 + "\033[0m")

        print(f"\033[96mTarget:\033[0m {scan_result['target']}")
        print(f"\033[96mScan Type:\033[0m {scan_result['scan_type']}")
        print(f"\033[96mDuration:\033[0m {scan_result['duration']:.2f} seconds")

        # WordPress information
        wp_info = scan_result["wordpress_info"]
        if wp_info:
            print("\n\033[92mWordPress Information:\033[0m")
            if "version" in wp_info:
                print(f"  \033[96mVersion:\033[0m {wp_info['version']}")
            if "theme" in wp_info:
                print(f"  \033[96mActive Theme:\033[0m {wp_info['theme']}")

        # Users found
        if scan_result["users"]:
            print(f"\n\033[92mUsers Found ({len(scan_result['users'])}):\033[0m")
            for user in scan_result["users"][:10]:  # Show first 10
                print(f"  • {user['username']}")
            if len(scan_result["users"]) > 10:
                print(f"  ... and {len(scan_result['users']) - 10} more")

        # Plugins found
        if scan_result["plugins"]:
            print(f"\n\033[92mPlugins Found ({len(scan_result['plugins'])}):\033[0m")
            for plugin in scan_result["plugins"][:5]:  # Show first 5
                version_info = (
                    f" (v{plugin['version']})" if plugin.get("version") else ""
                )
                print(f"  • {plugin['name']}{version_info}")
            if len(scan_result["plugins"]) > 5:
                print(f"  ... and {len(scan_result['plugins']) - 5} more")

        # Themes found
        if scan_result["themes"]:
            print(f"\n\033[92mThemes Found ({len(scan_result['themes'])}):\033[0m")
            for theme in scan_result["themes"]:
                version_info = f" (v{theme['version']})" if theme.get("version") else ""
                print(f"  • {theme['name']}{version_info}")

        # Vulnerabilities
        vuln_count = scan_result["summary"].get("vulnerability_count", 0)
        if vuln_count > 0:
            print(f"\n\033[91mVulnerabilities: {vuln_count} found\033[0m")
        elif scan_result["vulnerabilities"]:
            print("\n\033[93mScan Notes:\033[0m")
            for vuln in scan_result["vulnerabilities"]:
                print(f"  • {vuln['message']}")

        # Interesting entries
        if scan_result["interesting_entries"]:
            print("\n\033[93mInteresting Entries:\033[0m")
            for entry in scan_result["interesting_entries"][:3]:
                print(f"  • {entry}")

    def _view_scan_results(self):
        """View previous scan results"""
        if not self.scan_results:
            self.print_warning("No scan results available")
            return

        print("\n\033[93m" + "WPSCAN RESULTS HISTORY".center(60) + "\033[0m")
        print("\033[93m" + "-" * 60 + "\033[0m")

        for i, scan in enumerate(self.scan_results, 1):
            timestamp = scan["timestamp"][:19].replace("T", " ")
            users_count = len(scan["users"])
            plugins_count = len(scan["plugins"])

            print(f"\033[96m{i:2d}.\033[0m {scan['scan_type']} - {scan['target']}")
            print(f"     {timestamp} | Users: {users_count} | Plugins: {plugins_count}")

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
        print("3. Text Report")

        format_choice = self.get_user_input("Select format (1-3): ")

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get("output_dir", "./reports/output")

            if format_choice == "1":
                self._export_json(output_dir, timestamp)
            elif format_choice == "2":
                self._export_csv(output_dir, timestamp)
            elif format_choice == "3":
                self._export_text_report(output_dir, timestamp)
            else:
                self.print_error("Invalid format selection")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_json(self, output_dir: str, timestamp: str):
        """Export results to JSON format"""
        os.makedirs(output_dir, exist_ok=True)

        filename = f"wpscan_results_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            json.dump(self.scan_results, f, indent=2, default=str)

        self.print_success(f"Results exported to: {filepath}")

    def _export_csv(self, output_dir: str, timestamp: str):
        """Export results to CSV format"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"wpscan_results_{timestamp}.csv"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Timestamp",
                    "Target",
                    "Scan Type",
                    "WP Version",
                    "Theme",
                    "Users Count",
                    "Plugins Count",
                    "Themes Count",
                    "Duration",
                ]
            )

            for scan in self.scan_results:
                wp_info = scan["wordpress_info"]
                writer.writerow(
                    [
                        scan["timestamp"],
                        scan["target"],
                        scan["scan_type"],
                        wp_info.get("version", ""),
                        wp_info.get("theme", ""),
                        len(scan["users"]),
                        len(scan["plugins"]),
                        len(scan["themes"]),
                        f"{scan['duration']:.2f}s",
                    ]
                )

        self.print_success(f"Results exported to: {filepath}")

    def _export_text_report(self, output_dir: str, timestamp: str):
        """Export results as formatted text report"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"wpscan_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write("LEEGION FRAMEWORK - WPSCAN REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Scans: {len(self.scan_results)}\n\n")

            for i, scan in enumerate(self.scan_results, 1):
                f.write(f"\nSCAN {i}: {scan['scan_type']}\n")
                f.write("-" * 40 + "\n")
                f.write(f"Target: {scan['target']}\n")
                f.write(f"Timestamp: {scan['timestamp']}\n")
                f.write(f"Duration: {scan['duration']:.2f} seconds\n\n")

                # WordPress info
                wp_info = scan["wordpress_info"]
                if wp_info:
                    f.write("WordPress Information:\n")
                    if "version" in wp_info:
                        f.write(f"  Version: {wp_info['version']}\n")
                    if "theme" in wp_info:
                        f.write(f"  Theme: {wp_info['theme']}\n")
                    f.write("\n")

                # Users
                if scan["users"]:
                    f.write(f"Users Found ({len(scan['users'])}):\n")
                    for user in scan["users"]:
                        f.write(f"  - {user['username']}\n")
                    f.write("\n")

                # Plugins
                if scan["plugins"]:
                    f.write(f"Plugins Found ({len(scan['plugins'])}):\n")
                    for plugin in scan["plugins"]:
                        version_info = (
                            f" (v{plugin['version']})" if plugin.get("version") else ""
                        )
                        f.write(f"  - {plugin['name']}{version_info}\n")
                    f.write("\n")

                # Themes
                if scan["themes"]:
                    f.write(f"Themes Found ({len(scan['themes'])}):\n")
                    for theme in scan["themes"]:
                        version_info = (
                            f" (v{theme['version']})" if theme.get("version") else ""
                        )
                        f.write(f"  - {theme['name']}{version_info}\n")
                    f.write("\n")

        self.print_success(f"Report exported to: {filepath}")
