"""
Enhanced VPN Manager module for Leegion Framework
Supports OpenVPN with connection monitoring and status tracking

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import os
import subprocess
import threading
import signal
import time
import json
import sys
import requests
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from core.base_module import BaseModule
from core.banner import print_module_header, print_clean_menu_header
from core.security import network_rate_limiter


class VPNManager(BaseModule):
    """Enhanced VPN Manager with status monitoring and connection management"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "VPN_Manager")
        self.vpn_process = None
        self.vpn_thread = None
        self.monitoring_thread = None
        self.current_config = None
        self.connection_start_time = None
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
                f"\033[96mConnection Status:\033[0m {status_color}{status['status']}\033[0m"
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

        print(f"\n\033[96m📚 WHY USE VPN FOR SECURITY TESTING?\033[0m")
        print(
            "VPN (Virtual Private Network) is essential for ethical hacking because it:"
        )
        print("• Protects your real IP address from target systems and logs")
        print("• Encrypts traffic to prevent ISP monitoring of security activities")
        print("• Provides geographic location flexibility for testing")
        print("• Enables secure access to testing labs and remote networks")
        print(f"\n\033[93m🎯 REAL-WORLD USE CASES:\033[0m")
        print("• CTF competitions: Accessing challenge servers securely")
        print("• Bug bounty hunting: Protecting identity during reconnaissance")
        print("• Penetration testing: Connecting to client networks safely")
        print("• Security research: Anonymizing traffic for malware analysis")
        print("• Red team exercises: Simulating external attacker positioning")
        print(
            f"\n\033[91m⚠️  LEGAL REMINDER:\033[0m VPN protects you but doesn't make illegal activities legal!"
        )

        configs = self._get_vpn_configs()
        if not configs:
            self.print_error("No VPN configurations found.")
            self.print_info("Use option 6 to import VPN configurations.")
            self.print_info(
                "Popular VPN services for security testing: HackTheBox, TryHackMe, PentesterLab"
            )
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        print(f"\n\033[93m🔐 Available VPN configurations:\033[0m")
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
        print(f"\n\033[96m🖥️  VPN Connection Display Options:\033[0m")
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

                # Start OpenVPN process
                cmd = ["sudo", "openvpn", "--config", config["path"]]

                if display_mode == "2":  # Live Monitor Mode
                    self._run_live_monitor_mode(cmd, config)
                elif display_mode == "3":  # Status Monitor Mode
                    self._run_status_monitor_mode(cmd, config)
                else:  # Background Mode (default)
                    self._run_background_mode(cmd, config)

            except Exception as e:
                self.print_error(f"VPN connection failed: {e}")
                self._increment_stat("failed_connections")
                self.logger.error(f"VPN connection error: {e}")
            finally:
                self.vpn_process = None
                self.current_config = None
                if self.monitoring_thread:
                    self.monitoring_thread = None

        # Start VPN in background thread
        self.vpn_thread = threading.Thread(target=run_vpn, daemon=True)
        self.vpn_thread.start()

    def _run_background_mode(self, cmd: List[str], config: Dict[str, str]):
        """Run VPN in background mode (silent)"""
        self.vpn_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )

        self._increment_stat("total_connections")

        # Monitor VPN output silently
        if self.vpn_process.stdout:
            for line in self.vpn_process.stdout:
                line = line.strip()
                if line:
                    self.print_info(f"[VPN] {line}")

                    # Check for successful connection indicators
                    if "Initialization Sequence Completed" in line:
                        self.print_success("VPN connection established successfully!")
                        self._increment_stat("successful_connections")
                        self.logger.log_vpn_connection(config["name"], "connected")
                        self._start_connection_monitoring()

                    # Check for connection errors
                    elif "RESOLVE: Cannot resolve host address" in line:
                        self.print_error("DNS resolution failed for VPN server")
                    elif "AUTH_FAILED" in line:
                        self.print_error("Authentication failed - check credentials")
                    elif "TLS Error" in line:
                        self.print_error("TLS handshake failed")

        # Process ended
        return_code = self.vpn_process.wait()
        if return_code != 0:
            self._increment_stat("failed_connections")
            self.print_error(f"VPN process ended with code: {return_code}")
        else:
            self.print_info("VPN connection closed normally")

        self.logger.log_vpn_connection(config["name"], "disconnected")

    def _run_live_monitor_mode(self, cmd: List[str], config: Dict[str, str]):
        """Run VPN with live output monitoring"""
        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[96m🔴 LIVE VPN CONNECTION MONITOR\033[0m")
        print(f"\033[96mConfiguration:\033[0m {config['name']}")
        print(
            f"\033[96mPress Ctrl+C to return to menu (VPN will continue in background)\033[0m"
        )
        print(f"\033[93m{'='*65}\033[0m")

        self.vpn_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )

        self._increment_stat("total_connections")

        try:
            # Monitor VPN output in real-time
            if self.vpn_process.stdout:
                for line in self.vpn_process.stdout:
                    if line.strip():
                        timestamp = time.strftime("%H:%M:%S")
                        print(f"\033[90m[{timestamp}]\033[0m {line.rstrip()}")

                        # Check for important status messages
                        if "Initialization Sequence Completed" in line:
                            print(f"\033[92m✅ VPN CONNECTION ESTABLISHED!\033[0m")
                            self._increment_stat("successful_connections")
                            self.logger.log_vpn_connection(config["name"], "connected")
                        elif "AUTH_FAILED" in line:
                            print(f"\033[91m❌ AUTHENTICATION FAILED\033[0m")
                        elif "TLS Error" in line:
                            print(f"\033[91m❌ TLS HANDSHAKE ERROR\033[0m")

        except KeyboardInterrupt:
            print(
                f"\n\033[93m📱 Returning to menu - VPN continues in background\033[0m"
            )
            print(
                f"\033[93mUse 'Show Connection Status' to monitor or 'Disconnect VPN' to stop\033[0m"
            )

        # Process ended
        return_code = self.vpn_process.wait() if self.vpn_process else 0
        if return_code != 0:
            self._increment_stat("failed_connections")
            print(f"\033[91m❌ VPN process ended with code: {return_code}\033[0m")
        else:
            print(f"\033[96m✅ VPN connection closed normally\033[0m")

        self.logger.log_vpn_connection(config["name"], "disconnected")

    def _run_status_monitor_mode(self, cmd: List[str], config: Dict[str, str]):
        """Run VPN with simple status display matching option 3"""

        self.vpn_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )

        self._increment_stat("total_connections")

        # Connection tracking variables
        connection_status = "🟡 Connecting..."
        connection_established = False
        connection_start_time = time.time()
        last_status_update = time.time()

        try:
            # Check if there's already a VPN connection running
            system_status = self._get_connection_status()
            if system_status["connected"]:
                connection_status = "🟢 Connected (External)"
                connection_established = True
                self.print_info(
                    f"Detected existing VPN connection: {system_status['status']}"
                )

            # Initial display
            self._update_simple_vpn_display(
                terminal_width=80,
                config=config,
                connection_status=connection_status,
                connection_established=connection_established,
                connection_start_time=connection_start_time,
            )

            if self.vpn_process.stdout:
                for line in self.vpn_process.stdout:
                    if line.strip():
                        # Check for the definitive connection indicator
                        if "Initialization Sequence Completed" in line:
                            connection_status = "🟢 Connected"
                            if not connection_established:
                                connection_established = True
                                self._increment_stat("successful_connections")
                                self.logger.log_vpn_connection(
                                    config["name"], "connected"
                                )
                        elif "AUTH_FAILED" in line:
                            connection_status = "🔴 Auth Failed"
                        elif "TLS Error" in line:
                            connection_status = "🔴 TLS Error"
                        elif "Connecting to" in line:
                            connection_status = "🟡 Connecting..."
                        elif "TUN/TAP" in line:
                            connection_status = "🔵 Interface Ready"
                        elif "Route" in line and "added" in line:
                            connection_status = "🟢 Routes Added"

                        # Update display every 2 seconds to avoid flickering
                        current_time = time.time()
                        if current_time - last_status_update > 2.0:
                            # Check system status periodically
                            system_status = self._get_connection_status()
                            if (
                                system_status["connected"]
                                and not connection_established
                            ):
                                connection_status = "🟢 Connected (External)"
                                connection_established = True

                            # Update the display using the simple method
                            self._update_simple_vpn_display(
                                terminal_width=80,
                                config=config,
                                connection_status=connection_status,
                                connection_established=connection_established,
                                connection_start_time=connection_start_time,
                            )
                            last_status_update = current_time

        except KeyboardInterrupt:
            print(
                f"\n\033[93m📱 Returning to menu - VPN continues in background\033[0m"
            )
            if connection_established:
                print(f"\033[92m✅ VPN is connected and running\033[0m")
            else:
                print(f"\033[91m❌ VPN connection failed - check configuration\033[0m")
        finally:
            # Clean up
            pass

    def _update_simple_vpn_display(
        self,
        terminal_width,
        config,
        connection_status,
        connection_established,
        connection_start_time,
    ):
        """Display VPN status using the same format as 'Show Connection Status'"""
        try:
            # Get the same status information as option 3
            status = self._get_connection_status()
            status_color = "\033[92m" if status["connected"] else "\033[91m"

            # Clear screen and show header
            print("\033[2J\033[H", end="")  # Clear screen and move to top

            # Use the exact same format as _show_connection_status
            print(f"\n\033[93m{'VPN CONNECTION STATUS'.center(50)}\033[0m")
            print(f"\033[93m{'-'*50}\033[0m")
            print(f"\033[96mStatus:\033[0m {status_color}{status['status']}\033[0m")

            if status["connected"]:
                print(f"\033[96mConfiguration:\033[0m {status.get('config', 'N/A')}")
                print(f"\033[96mUptime:\033[0m {status.get('uptime', 'N/A')}")
                print(f"\033[96mProcess ID:\033[0m {status.get('pid', 'N/A')}")
                print(f"\033[96mVPN Interface:\033[0m {status.get('interface', 'N/A')}")
                print(f"\033[96mVPN IP:\033[0m {status.get('vpn_ip', 'N/A')}")
                print(f"\033[96mChecking public IP...\033[0m")

                # Get public IP information
                ip_info = self._get_ip_information()
                if ip_info:
                    print(f"\033[96mPublic IP:\033[0m {ip_info.get('ip', 'Unknown')}")
                    print(
                        f"\033[96mLocation:\033[0m {ip_info.get('location', 'Unknown')}"
                    )
                else:
                    print(f"\033[91mCould not retrieve public IP information\033[0m")
            else:
                print(
                    f"\033[96mLast Active:\033[0m {status.get('last_active', 'Never')}"
                )

            # Add connection monitor info
            print(f"\n\033[93m{'-'*50}\033[0m")
            print(f"\033[90m💡 Ctrl+C to return | VPN continues in background\033[0m")
            print(f"\033[90mTime: {time.strftime('%H:%M:%S')}\033[0m")

        except Exception as e:
            # Fallback to basic info
            print(f"\n\033[93m{'VPN CONNECTION STATUS'.center(50)}\033[0m")
            print(f"\033[93m{'-'*50}\033[0m")
            print(f"\033[96mStatus:\033[0m {connection_status}")
            print(f"\033[96mConfiguration:\033[0m {config['name']}")
            print(f"\033[91mError:\033[0m {str(e)}")
            print(f"\033[90m💡 Ctrl+C to return | VPN continues in background\033[0m")

    def _disconnect_vpn(self):
        """Disconnect active VPN connection and kill all VPN processes"""
        vpn_processes_found = False

        try:
            self.print_info("Checking for VPN processes...")

            # Check for framework-managed VPN process
            if self.vpn_process and self.vpn_process.poll() is None:
                vpn_processes_found = True
                self.print_info("Found framework-managed VPN process, disconnecting...")

                # Send SIGTERM to the process group
                os.killpg(os.getpgid(self.vpn_process.pid), signal.SIGTERM)

                # Wait for graceful shutdown
                try:
                    self.vpn_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if needed
                    os.killpg(os.getpgid(self.vpn_process.pid), signal.SIGKILL)
                    self.vpn_process.wait()

                # Update statistics
                if self.connection_start_time:
                    uptime = time.time() - self.connection_start_time
                    self._increment_stat("total_uptime", uptime)
                    self.connection_start_time = None

                self.print_success("Framework-managed VPN disconnected successfully")
                self.vpn_process = None
                self.current_config = None

            # Check for other OpenVPN processes
            try:
                openvpn_result = subprocess.run(
                    ["pgrep", "-f", "openvpn"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if openvpn_result.returncode == 0 and openvpn_result.stdout.strip():
                    pids = openvpn_result.stdout.strip().split("\n")
                    self.print_info(
                        f"Found {len(pids)} external OpenVPN process(es), killing them..."
                    )

                    for pid in pids:
                        try:
                            pid = int(pid.strip())
                            self.print_info(f"Killing OpenVPN process {pid}...")
                            os.kill(pid, signal.SIGTERM)

                            # Wait a moment for graceful shutdown
                            time.sleep(2)

                            # Check if process is still running and force kill if needed
                            try:
                                os.kill(pid, 0)  # Check if process exists
                                self.print_info(
                                    f"Force killing OpenVPN process {pid}..."
                                )
                                os.kill(pid, signal.SIGKILL)
                            except OSError:
                                # Process already terminated
                                pass

                        except (ValueError, OSError) as e:
                            self.print_warning(f"Could not kill process {pid}: {e}")

                    vpn_processes_found = True
                    self.print_success("External OpenVPN processes killed successfully")

            except subprocess.TimeoutExpired:
                self.print_warning("Timeout checking for OpenVPN processes")
            except Exception as e:
                self.print_warning(f"Error checking for OpenVPN processes: {e}")

            # Check for other VPN-related processes (WireGuard, etc.)
            try:
                # Check for WireGuard processes
                wireguard_result = subprocess.run(
                    ["pgrep", "-f", "wg"], capture_output=True, text=True, timeout=5
                )

                if wireguard_result.returncode == 0 and wireguard_result.stdout.strip():
                    pids = wireguard_result.stdout.strip().split("\n")
                    self.print_info(
                        f"Found {len(pids)} WireGuard process(es), killing them..."
                    )

                    for pid in pids:
                        try:
                            pid = int(pid.strip())
                            self.print_info(f"Killing WireGuard process {pid}...")
                            os.kill(pid, signal.SIGTERM)
                            time.sleep(1)

                            # Force kill if still running
                            try:
                                os.kill(pid, 0)
                                os.kill(pid, signal.SIGKILL)
                            except OSError:
                                pass

                        except (ValueError, OSError) as e:
                            self.print_warning(
                                f"Could not kill WireGuard process {pid}: {e}"
                            )

                    vpn_processes_found = True
                    self.print_success("WireGuard processes killed successfully")

            except subprocess.TimeoutExpired:
                self.print_warning("Timeout checking for WireGuard processes")
            except Exception as e:
                self.print_warning(f"Error checking for WireGuard processes: {e}")

            # Check for any remaining VPN-related processes
            try:
                vpn_keywords = ["vpn", "tunnel", "tun", "tap"]
                for keyword in vpn_keywords:
                    result = subprocess.run(
                        ["pgrep", "-f", keyword],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )

                    if result.returncode == 0 and result.stdout.strip():
                        pids = result.stdout.strip().split("\n")
                        # Filter out system processes and only kill user VPN processes
                        for pid in pids:
                            try:
                                pid = int(pid.strip())
                                # Check if it's a user process (not system process)
                                with open(f"/proc/{pid}/comm", "r") as f:
                                    comm = f.read().strip()

                                # Only kill if it looks like a VPN process
                                if any(
                                    vpn_term in comm.lower()
                                    for vpn_term in [
                                        "openvpn",
                                        "wireguard",
                                        "vpn",
                                        "tunnel",
                                    ]
                                ):
                                    self.print_info(
                                        f"Killing VPN-related process {pid} ({comm})..."
                                    )
                                    os.kill(pid, signal.SIGTERM)
                                    time.sleep(1)

                                    try:
                                        os.kill(pid, 0)
                                        os.kill(pid, signal.SIGKILL)
                                    except OSError:
                                        pass

                                    vpn_processes_found = True

                            except (ValueError, OSError, FileNotFoundError):
                                continue

            except Exception as e:
                self.print_warning(f"Error checking for other VPN processes: {e}")

            # Final status report
            if vpn_processes_found:
                self.print_success("All VPN processes have been terminated")

                # Verify no VPN processes remain
                try:
                    final_check = subprocess.run(
                        ["pgrep", "-f", "openvpn"],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )
                    if final_check.returncode == 0:
                        self.print_warning("Some VPN processes may still be running")
                    else:
                        self.print_success("No VPN processes found running")
                except:
                    pass

            else:
                self.print_info("No VPN processes were found running")

        except Exception as e:
            self.print_error(f"Error during VPN disconnection: {e}")
            self.logger.error(f"VPN disconnection error: {e}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _show_connection_status(self):
        """Show detailed connection status"""
        try:
            print(f"\n\033[93m{'VPN CONNECTION STATUS'.center(50)}\033[0m")
            print(f"\033[93m{'-'*50}\033[0m")
            status = self._get_connection_status()
            status_color = "\033[92m" if status["connected"] else "\033[91m"
            print(f"\033[96mStatus:\033[0m {status_color}{status['status']}\033[0m")
            if status["connected"]:
                print(f"\033[96mConfiguration:\033[0m {status.get('config', 'N/A')}")
                print(f"\033[96mUptime:\033[0m {status.get('uptime', 'N/A')}")
                print(f"\033[96mProcess ID:\033[0m {status.get('pid', 'N/A')}")
                print(f"\033[96mVPN Interface:\033[0m {status.get('interface', 'N/A')}")
                print(f"\033[96mVPN IP:\033[0m {status.get('vpn_ip', 'N/A')}")
                print(f"\033[96mChecking public IP...\033[0m")
                ip_info = self._get_ip_information()
                if ip_info:
                    print(f"\033[96mPublic IP:\033[0m {ip_info.get('ip', 'Unknown')}")
                    print(
                        f"\033[96mLocation:\033[0m {ip_info.get('location', 'Unknown')}"
                    )
                else:
                    print(f"\033[91mCould not retrieve public IP information\033[0m")
            else:
                print(
                    f"\033[96mLast Active:\033[0m {status.get('last_active', 'Never')}"
                )
        except Exception as e:
            print(f"\033[91m[ERROR]\033[0m Failed to get connection status: {e}")
            self.logger.error(f"Connection status error: {e}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _get_connection_status(self) -> Dict[str, Any]:
        """Get current VPN connection status with improved detection"""
        # First check if our managed VPN process is running
        if self.vpn_process and self.vpn_process.poll() is None:
            uptime = 0
            if self.connection_start_time:
                uptime = time.time() - self.connection_start_time
            # Get VPN interface info
            vpn_interface_info = self._get_vpn_interface_info()
            return {
                "connected": True,
                "status": "Connected (Framework Managed)",
                "config": (
                    self.current_config["name"] if self.current_config else "Unknown"
                ),
                "uptime": self._format_uptime(uptime),
                "pid": self.vpn_process.pid,
                "vpn_ip": vpn_interface_info.get("vpn_ip", "N/A"),
                "interface": vpn_interface_info.get("interface", "N/A"),
            }
        # Reset managed connection state if process is dead
        if self.vpn_process and self.vpn_process.poll() is not None:
            self.vpn_process = None
            self.current_config = None
            self.connection_start_time = None
        # Check for system VPN connections with more strict validation
        try:
            is_connected = False
            vpn_interface = None
            vpn_ip = None
            connection_type = None
            # Method 1: Check for active VPN routes instead of just processes
            route_result = subprocess.run(
                ["ip", "route", "show"], capture_output=True, text=True, timeout=5
            )
            # Look for VPN-like routes (not through main interface)
            if route_result.returncode == 0:
                route_lines = route_result.stdout.strip().split("\n")
                main_interface = None
                # Find main network interface
                for line in route_lines:
                    if "default via" in line:
                        parts = line.split()
                        if "dev" in parts:
                            dev_idx = parts.index("dev")
                            if dev_idx + 1 < len(parts):
                                main_interface = parts[dev_idx + 1]
                        break
                # Look for routes through tun/tap interfaces
                for line in route_lines:
                    if "dev tun" in line or "dev tap" in line:
                        # Extract interface name
                        parts = line.split()
                        if "dev" in parts:
                            dev_idx = parts.index("dev")
                            if dev_idx + 1 < len(parts):
                                interface = parts[dev_idx + 1]
                                # Verify this is actually a VPN interface with meaningful routes
                                if (
                                    "0.0.0.0/1" in line
                                    or "128.0.0.0/1" in line
                                    or interface.startswith("tun")
                                    or interface.startswith("tap")
                                ):
                                    is_connected = True
                                    vpn_interface = interface
                                    connection_type = f"System VPN ({interface})"
                                    break
            # Method 2: If no VPN routes found, check for OpenVPN processes more carefully
            if not is_connected:
                openvpn_result = subprocess.run(
                    ["pgrep", "-f", "openvpn.*--config"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if openvpn_result.returncode == 0 and openvpn_result.stdout.strip():
                    # Verify the process is actually connected by checking for established connections
                    netstat_result = subprocess.run(
                        ["ss", "-tuln"], capture_output=True, text=True, timeout=5
                    )
                    if netstat_result.returncode == 0:
                        # Look for OpenVPN typical ports or established connections
                        if (
                            ":1194" in netstat_result.stdout
                            or "openvpn" in netstat_result.stdout
                        ):
                            is_connected = True
                            connection_type = "External OpenVPN"
            # Method 3: Final check for tun/tap interfaces with IP assignments
            if not is_connected:
                try:
                    interfaces_result = subprocess.run(
                        ["ip", "addr", "show"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if interfaces_result.returncode == 0:
                        lines = interfaces_result.stdout.split("\n")
                        for line in lines:
                            if ("tun" in line or "tap" in line) and "inet " in line:
                                # Found a tun/tap interface with an IP
                                if "state UP" in line or "LOWER_UP" in line:
                                    parts = line.split()
                                    if parts:
                                        for part in parts:
                                            if part and (
                                                part.startswith("tun")
                                                or part.startswith("tap")
                                            ):
                                                vpn_interface = part.rstrip(":")
                                                is_connected = True
                                                connection_type = f"Active Interface ({vpn_interface})"
                                                break
                                        if is_connected:
                                            break
                except Exception:
                    pass
            # Try to get VPN IP if interface found
            if vpn_interface:
                # Try to get IP address for the interface
                try:
                    interfaces_result = subprocess.run(
                        ["ip", "addr", "show", vpn_interface],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if interfaces_result.returncode == 0:
                        for line in interfaces_result.stdout.split("\n"):
                            line = line.strip()
                            if line.startswith("inet "):
                                vpn_ip = line.split()[1].split("/")[0]
                                break
                except Exception:
                    pass
            # Return status based on findings
            if is_connected:
                uptime_str = "Unknown"
                if self.connection_start_time:
                    uptime = time.time() - self.connection_start_time
                    uptime_str = self._format_uptime(uptime)
                return {
                    "connected": True,
                    "status": f"Connected ({connection_type})",
                    "config": connection_type or "External VPN",
                    "uptime": uptime_str,
                    "pid": "N/A",
                    "vpn_ip": vpn_ip or "N/A",
                    "interface": vpn_interface or "N/A",
                }
            else:
                return {
                    "connected": False,
                    "status": "Disconnected",
                    "config": None,
                    "uptime": None,
                    "last_active": "No active VPN connection detected",
                    "pid": "N/A",
                    "vpn_ip": "N/A",
                    "interface": "N/A",
                }
        except Exception as e:
            self.logger.debug(f"Connection status check failed: {e}")
            return {
                "connected": False,
                "status": "Disconnected",
                "config": None,
                "uptime": None,
                "last_active": f"Status check error: {e}",
                "pid": "N/A",
                "vpn_ip": "N/A",
                "interface": "N/A",
            }

    def _get_ip_information(self) -> Optional[Dict[str, str]]:
        """Get public IP and location information with multiple fallback services"""
        # List of IP detection services with their parsers - ipapi.co first for location data
        services = [
            {
                "url": "https://ipapi.co/json/",
                "parser": lambda data: {
                    "ip": data.get("ip", "Unknown"),
                    "location": f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}",
                },
            },
            {
                "url": "https://ipinfo.io/json",
                "parser": lambda data: {
                    "ip": data.get("ip", "Unknown"),
                    "location": f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}",
                },
            },
            {
                "url": "https://api.ipify.org?format=json",
                "parser": lambda data: {
                    "ip": data.get("ip", "Unknown"),
                    "location": "Location unavailable",
                },
            },
            {
                "url": "https://httpbin.org/ip",
                "parser": lambda data: {
                    "ip": data.get("origin", "Unknown"),
                    "location": "Location unavailable",
                },
            },
        ]

        try:
            for service in services:
                try:
                    while not network_rate_limiter.allow():
                        time.sleep(0.05)
                    response = requests.get(service["url"], timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        result = service["parser"](data)
                        if result and result.get("ip") != "Unknown":
                            return result
                except Exception as e:
                    self.logger.debug(f"Failed to get IP from {service['url']}: {e}")
                    continue

        except Exception as e:
            self.logger.debug(f"Failed to import requests or get IP information: {e}")

        return None

    def _track_external_vpn_connection(self, is_connected: bool):
        """Track external VPN connections in statistics"""
        try:
            current_time = time.time()

            # If VPN is newly detected
            if is_connected and not self.connection_stats.get(
                "external_vpn_detected", False
            ):
                self.connection_stats["external_vpn_detected"] = True
                self.connection_stats["external_vpn_start_time"] = current_time
                self._increment_stat("total_connections")
                self._increment_stat("successful_connections")
                self.logger.info("External VPN connection detected and tracked")

            # If VPN was connected but now disconnected
            elif not is_connected and self.connection_stats.get(
                "external_vpn_detected", False
            ):
                self.connection_stats["external_vpn_detected"] = False
                if self.connection_stats.get("external_vpn_start_time"):
                    # Add to total uptime
                    uptime = (
                        current_time - self.connection_stats["external_vpn_start_time"]
                    )
                    self._increment_stat("total_uptime", uptime)
                    self.connection_stats["external_vpn_start_time"] = None
                self.logger.info("External VPN disconnection tracked")

            self.connection_stats["last_external_check"] = current_time

        except Exception as e:
            self.logger.error(f"Error tracking external VPN: {e}")

    def _list_vpn_configs(self):
        """List all available VPN configurations"""
        configs = self._get_vpn_configs()

        if not configs:
            self.print_warning("No VPN configurations found.")
            self.print_info("Place .ovpn files in the VPN config directory:")
            self.print_info(f"  {self.config.get('vpn_config_dir', './vpn_configs')}")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        print(f"\n\033[93m{'AVAILABLE VPN CONFIGURATIONS'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        for i, config in enumerate(configs, 1):
            size = self._get_file_size(config["path"])
            modified = self._get_file_modified_date(config["path"])
            print(f"\033[96m{i:2d}.\033[0m {config['name']}")
            print(f"     Path: {config['path']}")
            print(f"     Size: {size} | Modified: {modified}")
            print()

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _get_vpn_configs(self) -> List[Dict[str, str]]:
        """Get list of available VPN configuration files"""
        vpn_dir = self.config.get("vpn_config_dir", "./vpn_configs")

        if not os.path.exists(vpn_dir):
            os.makedirs(vpn_dir, exist_ok=True)
            return []

        configs = []
        for file in os.listdir(vpn_dir):
            if file.endswith(".ovpn"):
                full_path = os.path.join(vpn_dir, file)
                configs.append({"name": file, "path": full_path})

        return sorted(configs, key=lambda x: x["name"])

    def _show_connection_stats(self):
        """Show connection statistics"""
        try:
            print(f"\n\033[93m{'CONNECTION STATISTICS'.center(50)}\033[0m")
            print(f"\033[93m{'-'*50}\033[0m")

            stats = self.connection_stats.copy()

            # Calculate success rate
            total = stats["total_connections"]
            success_rate = (
                (stats["successful_connections"] / total * 100) if total > 0 else 0
            )

            # Format total uptime
            formatted_uptime = self._format_uptime(stats["total_uptime"])

            print(f"\033[96mTotal Connections:\033[0m {stats['total_connections']}")
            print(
                f"\033[96mSuccessful:\033[0m \033[92m{stats['successful_connections']}\033[0m"
            )
            print(
                f"\033[96mFailed:\033[0m \033[91m{stats['failed_connections']}\033[0m"
            )
            print(f"\033[96mSuccess Rate:\033[0m {success_rate:.1f}%")
            print(f"\033[96mTotal Uptime:\033[0m {formatted_uptime}")

            # Current session info (framework-managed)
            if self.connection_start_time:
                session_time = time.time() - self.connection_start_time
                session_formatted = self._format_uptime(session_time)
                print(f"\033[96mFramework Session:\033[0m {session_formatted}")
            else:
                print(f"\033[96mFramework Session:\033[0m Not connected")

            # External VPN session info
            if stats.get("external_vpn_start_time"):
                ext_session_time = time.time() - stats["external_vpn_start_time"]
                ext_session_formatted = self._format_uptime(ext_session_time)
                print(f"\033[96mExternal VPN Session:\033[0m {ext_session_formatted}")
            else:
                print(f"\033[96mExternal VPN Session:\033[0m Not detected")

            # System VPN info with enhanced detection and tracking
            try:
                system_status = self._get_connection_status()
                if system_status["connected"]:
                    print(f"\033[96mExternal VPN Detected:\033[0m \033[92mYes\033[0m")
                    print(f"\033[96mVPN Type:\033[0m {system_status['config']}")
                    if system_status.get("vpn_ip"):
                        print(
                            f"\033[96mVPN Interface IP:\033[0m {system_status['vpn_ip']}"
                        )

                    # Track external VPN connections in statistics
                    self._track_external_vpn_connection(True)
                else:
                    print(f"\033[96mExternal VPN Detected:\033[0m \033[91mNo\033[0m")
                    self._track_external_vpn_connection(False)
            except Exception as e:
                print(
                    f"\033[96mExternal VPN Detected:\033[0m \033[91mError checking: {e}\033[0m"
                )

        except Exception as e:
            print(f"\033[91m[ERROR]\033[0m Failed to show statistics: {e}")
            print(f"\033[96mConnection stats object:\033[0m {self.connection_stats}")
            self.logger.error(f"Statistics display error: {e}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _import_vpn_config(self):
        """Import a new VPN configuration file"""
        source_path = self.get_user_input(
            "Enter path to VPN configuration file: ", "file_path"
        )
        if not source_path:
            return

        if not source_path.endswith(".ovpn"):
            self.print_error("File must have .ovpn extension")
            return

        try:
            vpn_dir = self.config.get("vpn_config_dir", "./vpn_configs")
            os.makedirs(vpn_dir, exist_ok=True)

            filename = os.path.basename(source_path)
            dest_path = os.path.join(vpn_dir, filename)

            # Check if file already exists
            if os.path.exists(dest_path):
                overwrite = self.get_user_input(
                    f"File {filename} already exists. Overwrite? (y/N): "
                )
                if not overwrite or overwrite.lower() != "y":
                    return

            shutil.copy2(source_path, dest_path)
            self.print_success(f"VPN configuration imported: {filename}")

        except Exception as e:
            self.print_error(f"Failed to import configuration: {e}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _test_vpn_config(self):
        """Test a VPN configuration without connecting"""
        configs = self._get_vpn_configs()
        if not configs:
            self.print_error("No configurations available to test")
            return

        # Show configs and get selection
        self.print_info("Available configurations:")
        for i, config in enumerate(configs, 1):
            print(f"  {i}. {config['name']}")

        choice = self.get_user_input("Select configuration to test: ")
        if not choice or not choice.isdigit():
            return

        choice_idx = int(choice) - 1
        if choice_idx < 0 or choice_idx >= len(configs):
            self.print_error("Invalid selection")
            return

        config = configs[choice_idx]
        self._validate_vpn_config(config["path"])

    def _validate_vpn_config(self, config_path: str):
        """Validate VPN configuration file"""
        print(
            f"\n\033[93mTesting configuration: {os.path.basename(config_path)}\033[0m"
        )

        try:
            with open(config_path, "r") as f:
                content = f.read()

            # Basic validation checks
            checks = []
            if content:
                content_lower = content.lower()
                checks = [
                    ("Remote server", "remote " in content_lower),
                    (
                        "Certificate authority",
                        "ca " in content_lower or "<ca>" in content_lower,
                    ),
                    (
                        "Client certificate",
                        "cert " in content_lower or "<cert>" in content_lower,
                    ),
                    (
                        "Private key",
                        "key " in content_lower or "<key>" in content_lower,
                    ),
                    ("Protocol specified", "proto " in content_lower),
                ]

            print(f"\033[96mConfiguration validation:\033[0m")
            all_passed = True

            for check_name, passed in checks:
                status = "\033[92m✓\033[0m" if passed else "\033[91m✗\033[0m"
                print(f"  {check_name}: {status}")
                if not passed:
                    all_passed = False

            if all_passed:
                self.print_success("Configuration appears valid")
            else:
                self.print_warning("Configuration may have issues")

            # Try syntax check with OpenVPN (if available)
            try:
                result = subprocess.run(
                    ["openvpn", "--config", config_path, "--show-certs"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    self.print_success("OpenVPN syntax check passed")
                else:
                    self.print_warning("OpenVPN syntax check failed")
                    if result.stderr:
                        print(f"Error: {result.stderr}")

            except FileNotFoundError:
                self.print_info("OpenVPN not found - skipping syntax check")
            except subprocess.TimeoutExpired:
                self.print_warning("Syntax check timed out")

        except Exception as e:
            self.print_error(f"Error validating configuration: {e}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _export_connection_logs(self):
        """Export connection logs and statistics"""
        try:
            output_dir = self.config.get("output_dir", "./reports/output")
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vpn_logs_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)

            # Compile export data
            export_data = {
                "export_date": datetime.now().isoformat(),
                "statistics": self.connection_stats,
                "current_status": self._get_connection_status(),
                "available_configs": [
                    config["name"] for config in self._get_vpn_configs()
                ],
                "framework_version": "2.0",
            }

            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2)

            self.print_success(f"Connection logs exported to: {filepath}")

        except Exception as e:
            self.print_error(f"Failed to export logs: {e}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _start_connection_monitoring(self):
        """Start monitoring VPN connection health"""

        def monitor_connection():
            while self.vpn_process and self.vpn_process.poll() is None:
                time.sleep(30)  # Check every 30 seconds

                # Basic health check could be added here
                # For example, ping test, DNS resolution test, etc.

            # Connection ended
            if self.current_config:
                self.logger.info(
                    f"VPN monitoring ended for {self.current_config['name']}"
                )

        self.monitoring_thread = threading.Thread(
            target=monitor_connection, daemon=True
        )
        self.monitoring_thread.start()

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime duration"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            return f"{minutes}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"

    def _get_file_size(self, filepath: str) -> str:
        """Get formatted file size"""
        try:
            size_bytes = os.path.getsize(filepath)
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            else:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
        except:
            return "Unknown"

    def _get_file_modified_date(self, filepath: str) -> str:
        """Get formatted file modification date"""
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        except:
            return "Unknown"

    def _get_external_session_info(self) -> str:
        """Get external VPN session information"""
        try:
            stats = self.connection_stats
            if stats.get("external_vpn_start_time"):
                ext_session_time = time.time() - stats["external_vpn_start_time"]
                return self._format_uptime(ext_session_time)
            else:
                return "Not detected"
        except:
            return "Not detected"

    def _is_external_vpn_active(self) -> bool:
        """Check if external VPN is currently active"""
        try:
            status = self._get_connection_status()
            return status["connected"] and "External" in status.get("config", "")
        except:
            return False

    def _get_vpn_interface_info(self) -> Dict[str, str]:
        """Get VPN interface name and IP address - simplified and reliable"""
        try:
            # Simple method: just check for any tun/tap interface
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=3
            )

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.split("\n"):
                    if ("tun" in line or "tap" in line) and "UP" in line:
                        # Extract interface name
                        parts = line.split(":")
                        if len(parts) >= 2:
                            interface = parts[1].strip().split()[0]

                            # Try to get IP for this interface
                            try:
                                ip_result = subprocess.run(
                                    ["ip", "addr", "show", interface],
                                    capture_output=True,
                                    text=True,
                                    timeout=3,
                                )
                                if ip_result.returncode == 0 and ip_result.stdout:
                                    for ip_line in ip_result.stdout.split("\n"):
                                        if "inet " in ip_line and not "127." in ip_line:
                                            ip_parts = ip_line.strip().split()
                                            for part in ip_parts:
                                                if "/" in part and not part.startswith(
                                                    "127."
                                                ):
                                                    vpn_ip = part.split("/")[0]
                                                    return {
                                                        "interface": interface,
                                                        "vpn_ip": vpn_ip,
                                                    }
                            except:
                                pass

                            return {"interface": interface, "vpn_ip": "Connected"}

        except Exception as e:
            pass

        return {"interface": "Not detected", "vpn_ip": "Not available"}

    def _increment_stat(self, key: str, amount: float = 1):
        if key not in self.connection_stats or not isinstance(
            self.connection_stats[key], (int, float)
        ):
            self.connection_stats[key] = 0
        self.connection_stats[key] += amount
