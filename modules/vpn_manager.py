"""
VPN Manager Module for Leegion Framework

This module provides VPN connection management and configuration
capabilities for secure network operations.
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import subprocess
import threading
import requests
import shutil
from core.base_module import BaseModule
from core.banner import print_clean_menu_header


class VPNManager(BaseModule):
    """Enhanced VPN Manager with status monitoring and connection management"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "VPN_Manager")
        self.vpn_process: Optional[subprocess.Popen[str]] = None
        self.vpn_thread: Optional[threading.Thread] = None
        self.monitoring_thread: Optional[threading.Thread] = None
        self.current_config: Optional[Dict[str, str]] = None
        self.connection_start_time: Optional[float] = None
        self.connection_stats = {
            "total_connections": 0,
            "successful_connections": 0,
            "failed_connections": 0,
            "total_uptime": 0,
            "external_vpn_detected": False,
            "external_vpn_start_time": None,
            "last_external_check": None,
        }

    def run(self):
        """Main VPN manager interface"""
        while True:
            self._display_vpn_menu()
            choice = self.get_user_input("Select an option: ")

            if not choice:
                continue

            if choice == "1":
                self._connect_vpn()
            elif choice == "2":
                self._disconnect_vpn()
            elif choice == "3":
                self._show_connection_status()
            elif choice == "4":
                self._list_vpn_configs()
            elif choice == "5":
                self._show_connection_stats()
            elif choice == "6":
                self._import_vpn_config()
            elif choice == "7":
                self._test_vpn_config()
            elif choice == "8":
                self._export_connection_logs()
            elif choice == "0":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_vpn_menu(self):
        """Display VPN manager menu"""
        try:
            status = self._get_connection_status()
            status_color = "\033[92m" if status["connected"] else "\033[91m"

            print_clean_menu_header("VPN MANAGER", "Secure VPN Connection Management")
            print(
                f"\033[96mConnection Status:\033[0m "
                f"{status_color}{status['status']}\033[0m"
            )
            if status["connected"]:
                print(f"\033[96mActive Config:\033[0m {status['config']}")
                print(f"\033[96mUptime:\033[0m {status['uptime']}")
            print(f"\033[93m{'-'*65}\033[0m")
            print("\033[96m1.\033[0m Connect to VPN")
            print("\033[96m2.\033[0m Disconnect VPN")
            print("\033[96m3.\033[0m Show Connection Status")
            print("\033[96m4.\033[0m List Available Configurations")
            print("\033[96m5.\033[0m Show Connection Statistics")
            print("\033[96m6.\033[0m Import VPN Configuration")
            print("\033[96m7.\033[0m Test VPN Configuration")
            print("\033[96m8.\033[0m Export Connection Logs")
            print("\033[96m0.\033[0m Back to Main Menu")
            print(f"\033[96m{'='*65}\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR]\033[0m Menu display error: {e}")
            print(f"\033[93m{'-'*65}\033[0m")
            print("\033[96m0.\033[0m Back to Main Menu")
            print(f"\033[96m{'='*65}\033[0m")

    def _connect_vpn(self):
        """Connect to a VPN configuration"""
        if self.vpn_process and self.vpn_process.poll() is None:
            self.print_warning("VPN is already connected. Disconnect first.")
            return

        print("\n\033[96m📚 WHY USE VPN FOR SECURITY TESTING?\033[0m")
        print("\n\033[93m🎯 REAL-WORLD USE CASES:\033[0m")
        print(
            "\n\033[91m⚠️  LEGAL REMINDER:\033[0m VPN protects you but doesn't make "
            "illegal activities legal!"
        )

        configs = self._get_vpn_configs()
        if not configs:
            self.print_error("No VPN configurations found.")
            self.print_info("Use option 6 to import VPN configurations.")
            self.print_info(
                "Popular VPN services for security testing: HackTheBox, "
                "TryHackMe, PentesterLab"
            )
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        print("\n\033[93m🔐 Available VPN configurations:\033[0m")
        for i, config in enumerate(configs, 1):
            print(f"  {i}. {config['name']}")

        choice = self.get_user_input("\nSelect configuration number: ")
        if not choice or not choice.isdigit():
            self.print_info("Configuration selection cancelled.")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        choice_idx = int(choice) - 1
        if choice_idx < 0 or choice_idx >= len(configs):
            self.print_error("Invalid configuration selection.")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        selected_config = configs[choice_idx]

        # Ask for connection display mode
        print("\n\033[96m🖥️  VPN Connection Display Options:\033[0m")
        print("1. Background Mode (silent connection)")
        print("2. Live Monitor Mode (real-time output display)")
        print("3. Status Monitor Mode (connection status display)")

        display_choice = (
            self.get_user_input("\nSelect display mode (1-3): ", required=False) or "1"
        )

        if display_choice in ["1", "2", "3"]:
            self.print_info(f"Starting VPN connection to: {selected_config['name']}")
            self.print_info(f"Display mode: {display_choice}")
            self._start_vpn_connection(selected_config, display_choice)

            # Give user feedback about the connection attempt
            if display_choice == "1":  # Background mode
                self.print_success("VPN connection started in background mode")
                self.print_info(
                    "Use 'Show Connection Status' to check connection status"
                )
            elif display_choice == "2":  # Live monitor mode
                self.print_success("VPN connection started in live monitor mode")
                self.print_info("You will see real-time connection output")
            elif display_choice == "3":  # Status monitor mode
                self.print_success("VPN connection started in status monitor mode")
                self.print_info("Connection status will be displayed")
        else:
            self.print_error("Invalid display mode. Using background mode.")
            self._start_vpn_connection(selected_config, "1")
            self.print_success("VPN connection started in background mode")
            self.print_info("Use 'Show Connection Status' to check connection status")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _start_vpn_connection(self, config: Dict[str, str], display_mode: str = "1"):
        """Start VPN connection with different display modes"""
        self.current_config = config
        self.connection_start_time = time.time()

        def run_vpn():
            try:
                self.print_info(f"Connecting to VPN: {config['name']}")
                self.logger.log_vpn_connection(config["name"], "connecting")

                # Check if config file exists
                if not os.path.exists(config["path"]):
                    self.print_error(f"Configuration file not found: {config['path']}")
                    return

                # Build OpenVPN command
                cmd = [
                    "sudo",
                    "openvpn",
                    "--config",
                    config["path"],
                    "--auth-nocache",
                    "--persist-tun",
                    "--persist-key",
                ]

                # Add credentials if provided
                if config.get("username") and config.get("password"):
                    cmd.extend(["--auth-user-pass", config["auth_file"]])

                # Start connection based on display mode
                if display_mode == "1":
                    self._run_background_mode(cmd, config)
                elif display_mode == "2":
                    self._run_live_monitor_mode(cmd, config)
                elif display_mode == "3":
                    self._run_status_monitor_mode(cmd, config)

            except Exception as e:
                self.print_error(f"VPN connection failed: {e}")
                self.logger.log_vpn_connection(config["name"], "failed")

        # Start VPN connection in a separate thread
        self.vpn_thread = threading.Thread(target=run_vpn, daemon=True)
        self.vpn_thread.start()

    def _run_background_mode(self, cmd: List[str], config: Dict[str, str]):
        """Run VPN in background mode"""
        try:
            self.vpn_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Wait a moment for connection to establish
            time.sleep(3)

            if self.vpn_process.poll() is None:
                self.print_success(f"Connected to {config['name']}")
                self.connection_stats["successful_connections"] += 1
                self.connection_stats["total_connections"] += 1
                self.logger.log_vpn_connection(config["name"], "connected")

                # Start monitoring
                self._start_connection_monitoring()
            else:
                self.print_error(f"Failed to connect to {config['name']}")
                self.connection_stats["failed_connections"] += 1
                self.connection_stats["total_connections"] += 1
                self.logger.log_vpn_connection(config["name"], "failed")

        except Exception as e:
            self.print_error(f"Background mode error: {e}")

    def _run_live_monitor_mode(self, cmd: List[str], config: Dict[str, str]):
        """Run VPN with live output monitoring"""
        try:
            self.vpn_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            self.print_info("Live monitoring started. Press Ctrl+C to stop.")

            # Monitor output in real-time
            if self.vpn_process.stdout:
                for line in iter(self.vpn_process.stdout.readline, ""):
                    if line:
                        print(f"VPN: {line.strip()}")

                        # Check for connection success/failure indicators
                        if "Initialization Sequence Completed" in line:
                            self.print_success(f"Connected to {config['name']}")
                            self.connection_stats["successful_connections"] += 1
                            self.connection_stats["total_connections"] += 1
                            self.logger.log_vpn_connection(config["name"], "connected")
                            break
                        elif "ERROR" in line or "FATAL" in line:
                            self.print_error(f"Connection error: {line.strip()}")
                            self.connection_stats["failed_connections"] += 1
                            self.connection_stats["total_connections"] += 1
                            self.logger.log_vpn_connection(config["name"], "failed")
                            break

        except KeyboardInterrupt:
            self.print_info("Live monitoring stopped by user")
        except Exception as e:
            self.print_error(f"Live monitor mode error: {e}")

    def _run_status_monitor_mode(self, cmd: List[str], config: Dict[str, str]):
        """Run VPN with status monitoring display"""
        try:
            self.vpn_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            self.print_info("Status monitoring started. Press Ctrl+C to stop.")

            # Monitor connection status
            start_time = time.time()
            while self.vpn_process.poll() is None:
                try:
                    # Clear screen and show status
                    os.system("clear")
                    self._update_simple_vpn_display(
                        80, config, "Connecting", False, start_time
                    )

                    time.sleep(1)

                except KeyboardInterrupt:
                    break

            # Check final status
            if self.vpn_process.returncode == 0:
                self.print_success(f"Connected to {config['name']}")
                self.connection_stats["successful_connections"] += 1
                self.connection_stats["total_connections"] += 1
                self.logger.log_vpn_connection(config["name"], "connected")
            else:
                self.print_error(f"Failed to connect to {config['name']}")
                self.connection_stats["failed_connections"] += 1
                self.connection_stats["total_connections"] += 1
                self.logger.log_vpn_connection(config["name"], "failed")

        except Exception as e:
            self.print_error(f"Status monitor mode error: {e}")

    def _update_simple_vpn_display(
        self,
        terminal_width,
        config,
        connection_status,
        connection_established,
        connection_start_time,
    ):
        """Update simple VPN status display"""
        print("=" * terminal_width)
        print("VPN CONNECTION STATUS".center(terminal_width))
        print("=" * terminal_width)
        print(f"Configuration: {config['name']}")
        print(f"Status: {connection_status}")
        print(f"Established: {'Yes' if connection_established else 'No'}")

        if connection_start_time:
            elapsed = time.time() - connection_start_time
            print(f"Elapsed Time: {self._format_uptime(elapsed)}")

        print("=" * terminal_width)
        print("Press Ctrl+C to stop monitoring")
        print("=" * terminal_width)

    def _disconnect_vpn(self):
        """Disconnect from VPN"""
        if not self.vpn_process or self.vpn_process.poll() is not None:
            self.print_info("No active VPN connection to disconnect.")
            return

        try:
            self.print_info("Disconnecting VPN...")

            # Send SIGTERM to VPN process
            self.vpn_process.terminate()

            # Wait for graceful shutdown
            try:
                self.vpn_process.wait(timeout=10)
                self.print_success("VPN disconnected successfully.")
            except subprocess.TimeoutExpired:
                # Force kill if graceful shutdown fails
                self.print_warning("Force killing VPN process...")
                self.vpn_process.kill()
                self.vpn_process.wait()
                self.print_success("VPN disconnected (force kill).")

            # Reset connection tracking
            self.vpn_process = None
            self.current_config = None
            self.connection_start_time = None

            # Log disconnection
            if self.current_config:
                self.logger.log_vpn_connection(
                    self.current_config["name"], "disconnected"
                )

        except Exception as e:
            self.print_error(f"Error disconnecting VPN: {e}")

    def _show_connection_status(self):
        """Show current VPN connection status"""
        try:
            status = self._get_connection_status()
            status_color = "\033[92m" if status["connected"] else "\033[91m"

            print(f"\n\033[93m{'VPN CONNECTION STATUS'.center(50)}\033[0m")
            print(f"\033[93m{'-'*50}\033[0m")
            print(f"\033[96mStatus:\033[0m {status_color}{status['status']}\033[0m")

            if status["connected"]:
                print(f"\033[96mConfiguration:\033[0m {status.get('config', 'N/A')}")
                print(f"\033[96mUptime:\033[0m {status.get('uptime', 'N/A')}")
                print(f"\033[96mProcess ID:\033[0m {status.get('pid', 'N/A')}")
                print(f"\033[96mVPN Interface:\033[0m {status.get('interface', 'N/A')}")
                print(f"\033[96mVPN IP:\033[0m {status.get('vpn_ip', 'N/A')}")
                print("\033[96mChecking public IP...\033[0m")

                # Get public IP information
                ip_info = self._get_ip_information()
                if ip_info:
                    print(f"\033[96mPublic IP:\033[0m {ip_info.get('ip', 'Unknown')}")
                    print(
                        f"\033[96mLocation:\033[0m {ip_info.get('location', 'Unknown')}"
                    )
                else:
                    print("\033[91mCould not retrieve public IP information\033[0m")
            else:
                print(
                    f"\033[96mLast Active:\033[0m {status.get('last_active', 'Never')}"
                )

            print(f"\033[93m{'-'*50}\033[0m")

        except Exception as e:
            self.print_error(f"Error getting connection status: {e}")

    def _get_connection_status(self) -> Dict[str, Any]:
        """Get comprehensive VPN connection status"""
        status = {
            "connected": False,
            "status": "Disconnected",
            "config": "N/A",
            "uptime": "N/A",
            "pid": "N/A",
            "interface": "N/A",
            "vpn_ip": "N/A",
            "last_active": "Never",
        }

        try:
            # Check if our VPN process is running
            if self.vpn_process and self.vpn_process.poll() is None:
                status["connected"] = True
                status["status"] = "Connected (Leegion VPN)"
                status["pid"] = str(self.vpn_process.pid)

                if self.current_config:
                    status["config"] = self.current_config["name"]

                if self.connection_start_time:
                    uptime = time.time() - self.connection_start_time
                    status["uptime"] = self._format_uptime(uptime)

            # Check for external VPN connections
            external_vpn = self._is_external_vpn_active()
            if external_vpn:
                status["connected"] = True
                status["status"] = "Connected (External VPN)"
                status["config"] = "External VPN"

                # Get external VPN info
                external_info = self._get_external_session_info()
                if external_info:
                    status["uptime"] = external_info

            # Get VPN interface information
            if status["connected"]:
                interface_info = self._get_vpn_interface_info()
                status["interface"] = interface_info.get("interface", "N/A")
                status["vpn_ip"] = interface_info.get("ip", "N/A")

            return status

        except Exception as e:
            self.print_error(f"Error getting connection status: {e}")
            return status

    def _get_ip_information(self) -> Optional[Dict[str, str]]:
        """Get current public IP information"""
        try:
            # Try multiple IP check services for reliability
            services = [
                "https://ipinfo.io/json",
                "https://api.ipify.org?format=json",
                "https://httpbin.org/ip",
            ]

            for service in services:
                try:
                    response = requests.get(service, timeout=10)
                    if response.status_code == 200:
                        data = response.json()

                        if service == "https://ipinfo.io/json":
                            return {
                                "ip": data.get("ip", "Unknown"),
                                "location": (
                                    f"{data.get('city', 'Unknown')}, "
                                    f"{data.get('country', 'Unknown')}"
                                ),
                            }
                        elif service == "https://api.ipify.org?format=json":
                            return {
                                "ip": data.get("ip", "Unknown"),
                                "location": "Unknown",
                            }
                        elif service == "https://httpbin.org/ip":
                            return {
                                "ip": data.get("origin", "Unknown"),
                                "location": "Unknown",
                            }

                except Exception:
                    continue

            return None

        except Exception as e:
            self.print_error(f"Error getting IP information: {e}")
            return None

    def _track_external_vpn_connection(self, is_connected: bool):
        """Track external VPN connection status"""
        if is_connected and not self.connection_stats["external_vpn_detected"]:
            self.connection_stats["external_vpn_detected"] = True
            self.connection_stats["external_vpn_start_time"] = time.time()
            self.print_info("External VPN connection detected")
        elif not is_connected and self.connection_stats["external_vpn_detected"]:
            self.connection_stats["external_vpn_detected"] = False
            self.connection_stats["external_vpn_start_time"] = None
            self.print_info("External VPN connection lost")

        self.connection_stats["last_external_check"] = time.time()

    def _list_vpn_configs(self):
        """List available VPN configurations"""
        configs = self._get_vpn_configs()

        if not configs:
            self.print_info("No VPN configurations found.")
            self.print_info("Use option 6 to import VPN configurations.")
            return

        print(f"\n\033[93m{'AVAILABLE VPN CONFIGURATIONS'.center(50)}\033[0m")
        print(f"\033[93m{'-'*50}\033[0m")

        for i, config in enumerate(configs, 1):
            print(f"\n\033[96m{i}. {config['name']}\033[0m")
            print(f"   Path: {config['path']}")
            print(f"   Size: {self._get_file_size(config['path'])}")
            print(f"   Modified: {self._get_file_modified_date(config['path'])}")

            if config.get("username"):
                print(f"   Username: {config['username']}")
            else:
                print("   Username: Not configured")

        print(f"\n\033[93m{'-'*50}\033[0m")

    def _get_vpn_configs(self) -> List[Dict[str, str]]:
        """Get list of available VPN configurations"""
        configs = []
        config_dir = self.config.get("vpn_config_dir", "./vpn_configs")

        if os.path.exists(config_dir):
            for file in os.listdir(config_dir):
                if file.endswith((".ovpn", ".conf")):
                    config_path = os.path.join(config_dir, file)
                    configs.append(
                        {
                            "name": os.path.splitext(file)[0],
                            "path": config_path,
                            "username": "",
                            "password": "",
                            "auth_file": "",
                        }
                    )

        return configs

    def _show_connection_stats(self):
        """Show VPN connection statistics"""
        stats = self.connection_stats

        print(f"\n\033[93m{'VPN CONNECTION STATISTICS'.center(50)}\033[0m")
        print(f"\033[93m{'-'*50}\033[0m")

        print(f"\033[96mTotal Connections:\033[0m {stats['total_connections']}")
        print(f"\033[96mSuccessful:\033[0m {stats['successful_connections']}")
        print(f"\033[96mFailed:\033[0m {stats['failed_connections']}")

        if stats["total_connections"] > 0:
            success_rate = (
                stats["successful_connections"] / stats["total_connections"]
            ) * 100
            print(f"\033[96mSuccess Rate:\033[0m {success_rate:.1f}%")

        print(
            f"\033[96mTotal Uptime:\033[0m {self._format_uptime(stats['total_uptime'])}"
        )

        if stats["external_vpn_detected"]:
            print("\033[96mExternal VPN:\033[0m Active")
            if stats["external_vpn_start_time"]:
                external_uptime = time.time() - stats["external_vpn_start_time"]
                print(
                    f"\033[96mExternal Uptime:\033[0m "
                    f"{self._format_uptime(external_uptime)}"
                )
        else:
            print("\033[96mExternal VPN:\033[0m Not detected")

        print(f"\033[93m{'-'*50}\033[0m")

    def _import_vpn_config(self):
        """Import VPN configuration file"""
        print("\n\033[96m📁 VPN Configuration Import\033[0m")
        print("\nSupported formats: .ovpn, .conf")
        print("Common locations:")
        print("  - ~/Downloads/")
        print("  - ~/Desktop/")
        print("  - /tmp/")

        config_path = self.get_user_input("\nEnter path to VPN config file: ")
        if not config_path:
            self.print_info("Import cancelled.")
            return

        if not os.path.exists(config_path):
            self.print_error("Configuration file not found.")
            return

        if not config_path.endswith((".ovpn", ".conf")):
            self.print_error("Unsupported file format. Use .ovpn or .conf files.")
            return

        try:
            # Validate configuration
            if self._validate_vpn_config(config_path):
                # Copy to VPN config directory
                config_dir = self.config.get("vpn_config_dir", "./vpn_configs")
                os.makedirs(config_dir, exist_ok=True)

                filename = os.path.basename(config_path)
                dest_path = os.path.join(config_dir, filename)

                shutil.copy2(config_path, dest_path)

                self.print_success(f"Configuration imported: {filename}")
                self.print_info(f"Location: {dest_path}")
            else:
                self.print_error("Configuration validation failed.")

        except Exception as e:
            self.print_error(f"Import failed: {e}")

    def _test_vpn_config(self):
        """Test VPN configuration without connecting"""
        configs = self._get_vpn_configs()

        if not configs:
            self.print_info("No VPN configurations to test.")
            return

        print("\n\033[96m🔧 VPN Configuration Test\033[0m")
        print("\nAvailable configurations:")

        for i, config in enumerate(configs, 1):
            print(f"  {i}. {config['name']}")

        choice = self.get_user_input("\nSelect configuration to test: ")
        if not choice or not choice.isdigit():
            self.print_info("Test cancelled.")
            return

        choice_idx = int(choice) - 1
        if choice_idx < 0 or choice_idx >= len(configs):
            self.print_error("Invalid selection.")
            return

        selected_config = configs[choice_idx]
        self.print_info(f"Testing configuration: {selected_config['name']}")

        if self._validate_vpn_config(selected_config["path"]):
            self.print_success("Configuration is valid!")
        else:
            self.print_error("Configuration has issues.")

    def _validate_vpn_config(self, config_path: str):
        """Validate VPN configuration file"""
        try:
            # Check if OpenVPN can parse the configuration
            result = subprocess.run(
                ["openvpn", "--config", config_path, "--test-crypto"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                return True
            else:
                self.print_error(f"Configuration error: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            self.print_error("Configuration test timed out.")
            return False
        except FileNotFoundError:
            self.print_error("OpenVPN not found. Please install OpenVPN.")
            return False
        except Exception as e:
            self.print_error(f"Validation error: {e}")
            return False

    def _export_connection_logs(self):
        """Export VPN connection logs"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vpn_logs_{timestamp}.json"

            export_data = {
                "connection_stats": self.connection_stats,
                "current_config": self.current_config,
                "exported_at": datetime.now().isoformat(),
            }

            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2)

            self.print_success(f"Connection logs exported to: {filename}")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _start_connection_monitoring(self):
        """Start background connection monitoring"""

        def monitor_connection():
            while self.vpn_process and self.vpn_process.poll() is None:
                try:
                    # Update uptime
                    if self.connection_start_time:
                        self.connection_stats["total_uptime"] = (
                            time.time() - self.connection_start_time
                        )

                    # Check for external VPN
                    external_vpn = self._is_external_vpn_active()
                    self._track_external_vpn_connection(external_vpn)

                    time.sleep(5)  # Check every 5 seconds

                except Exception:
                    break

        self.monitoring_thread = threading.Thread(
            target=monitor_connection, daemon=True
        )
        self.monitoring_thread.start()

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"

    def _get_file_size(self, filepath: str) -> str:
        """Get human readable file size"""
        try:
            size = os.path.getsize(filepath)
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        except Exception:
            return "Unknown"

    def _get_file_modified_date(self, filepath: str) -> str:
        """Get file modification date"""
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    def _get_external_session_info(self) -> str:
        """Get external VPN session information"""
        try:
            if self.connection_stats["external_vpn_start_time"]:
                uptime = time.time() - self.connection_stats["external_vpn_start_time"]
                return self._format_uptime(uptime)
            return "Unknown"
        except Exception:
            return "Unknown"

    def _is_external_vpn_active(self) -> bool:
        """Check if external VPN is active"""
        try:
            # Check for OpenVPN processes
            result = subprocess.run(
                ["pgrep", "-f", "openvpn"], capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_vpn_interface_info(self) -> Dict[str, str]:
        """Get VPN interface information"""
        info = {"interface": "N/A", "ip": "N/A"}

        try:
            # Check for tun/tap interfaces
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "tun" in line or "tap" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            info["interface"] = parts[1].strip()
                            break

            # Get IP address for VPN interface
            if info["interface"] != "N/A":
                ip_result = subprocess.run(
                    ["ip", "addr", "show", info["interface"]],
                    capture_output=True,
                    text=True,
                )

                if ip_result.returncode == 0:
                    for line in ip_result.stdout.split("\n"):
                        if "inet " in line:
                            ip_parts = line.strip().split()
                            if len(ip_parts) >= 2:
                                info["ip"] = ip_parts[1].split("/")[0]
                                break

        except Exception:
            pass

        return info

    def _increment_stat(self, key: str, amount: float = 1):
        """Increment connection statistic"""
        if key in self.connection_stats:
            self.connection_stats[key] += amount
