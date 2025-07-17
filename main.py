#!/usr/bin/env python3
"""
Leegion Framework - Enhanced Cybersecurity Toolkit
Main entry point for the application

Author: Leegion
Project: Leegion Framework v2.0
GitHub: https://github.com/Leegion/leegion-framework
License: MIT License

Copyright (c) 2025 Leegion. All rights reserved.
This project is the intellectual property of Leegion.
"""

import sys
import os
import argparse
import time
import subprocess
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.logger import setup_logger
from core.banner import print_banner, clear_screen, print_clean_menu_header
from core.utils import check_and_install_packages, handle_keyboard_interrupt
from config.settings import load_config, save_config, create_directories_from_config
from modules.vpn_manager import VPNManager
from modules.nmap_scanner import NmapScanner
from modules.wpscan_integration import WPScanIntegration
from modules.subdomain_enum import SubdomainEnumerator
from modules.directory_bruteforce import DirectoryBruteforcer
from modules.ssl_analyzer import SSLAnalyzer
from modules.command_helper import CommandHelper
from modules.file_downloader import FileDownloader
from modules.reverse_shell_generator import ReverseShellGenerator
from reports.report_generator import ReportGenerator
from core.signature import verify_leegion_ownership, generate_leegion_watermark
from core.monitoring import initialize_monitoring, get_monitoring_system
from core.backup import initialize_backup_manager, get_backup_manager


class LeegionFramework:
    """Main framework class that orchestrates all modules"""

    def __init__(self, config_path=None, logger=None):
        # Determine config path based on installation type
        if config_path is None:
            # Check if running from installed location
            if os.path.exists("/opt/leegion-framework"):
                # Try user config first, then system config
                user_config = os.path.expanduser("~/.config/leegion/config.json")
                system_config = "config/config.json"
                config_path = (
                    user_config if os.path.exists(user_config) else system_config
                )
            else:
                # Running from source directory
                config_path = "config/config.json"
        self.config = load_config(config_path)
        self.logger = logger or setup_logger(self.config.get("log_level", "INFO"))
        self.report_generator = ReportGenerator()

        # Leegion's ownership verification
        self.ownership = verify_leegion_ownership()
        self.logger.info(
            f"Framework initialized by {self.ownership['author']} - {self.ownership['framework_id']}"
        )

        # Initialize modules
        self.modules = {
            "vpn": VPNManager(self.config),
            "nmap": NmapScanner(self.config),
            "wpscan": WPScanIntegration(self.config),
            "subdomain": SubdomainEnumerator(self.config),
            "dirbrute": DirectoryBruteforcer(self.config),
            "ssl": SSLAnalyzer(self.config),
            "helper": CommandHelper(self.config),
            "downloader": FileDownloader(self.config),
            "revshell": ReverseShellGenerator(self.config),
        }

        self.logger.info("Leegion Framework initialized successfully")

    def display_menu(self):
        """Display the main menu with clean formatting"""
        print_clean_menu_header(
            "LEEGION FRAMEWORK MENU", "Enhanced Cybersecurity Toolkit"
        )
        print(
            "\033[93m💡 NEW TO CYBERSECURITY?\033[0m Visit \033[92mtryhackme.com\033[0m for hands-on learning!"
        )
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m1.\033[0m  VPN Manager")
        print("\033[96m2.\033[0m  Network Scanner (Nmap)")
        print("\033[96m3.\033[0m  WordPress Scanner (WPScan)")
        print("\033[96m4.\033[0m  Subdomain Enumerator")
        print("\033[96m5.\033[0m  Directory Bruteforcer")
        print("\033[96m6.\033[0m  SSL/TLS Analyzer")
        print("\033[96m7.\033[0m  Command Helper & Cheatsheet")
        print("\033[96m8.\033[0m  File Downloader (Rate Limit Bypass)")
        print("\033[96m9.\033[0m  Reverse Shell Generator")
        print("\033[96m10.\033[0m Generate Report")
        print("\033[96m11.\033[0m Settings & Configuration")
        print("\033[96m0.\033[0m  Exit Framework")
        print(f"\033[96m{'='*65}\033[0m")

    def handle_settings_menu(self):
        """Handle settings and configuration menu"""
        while True:
            print_clean_menu_header(
                "SETTINGS & CONFIGURATION", "Framework Configuration Manager"
            )
            print("\033[96m1.\033[0m View Current Configuration")
            print("\033[96m2.\033[0m Update Log Level")
            print("\033[96m3.\033[0m Update VPN Config Directory")
            print("\033[96m4.\033[0m Update Output Directory")
            print("\033[96m5.\033[0m Reset to Defaults")
            print("\033[96m6.\033[0m System Installation Manager")
            print("\033[96m0.\033[0m Back to Main Menu")
            print(f"\033[96m{'='*65}\033[0m")

            choice = input("\033[93mEnter your choice: \033[0m").strip()

            if choice == "1":
                self._display_config()
                input("\n\033[93mPress Enter to continue...\033[0m")
            elif choice == "2":
                self._update_log_level()
            elif choice == "3":
                self._update_vpn_dir()
            elif choice == "4":
                self._update_output_dir()
            elif choice == "5":
                self._reset_config()
            elif choice == "6":
                self._system_installation_manager()
            elif choice == "0":
                break
            else:
                print("\033[91m[!]\033[0m Invalid choice. Please try again.")
                input("\n\033[93mPress Enter to continue...\033[0m")

    def _display_config(self):
        """Display current configuration"""
        print("\n\033[92m--- Current Configuration ---\033[0m")
        for key, value in self.config.items():
            print(f"\033[96m{key}:\033[0m {value}")

    def _update_log_level(self):
        """Update logging level"""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        print(f"\nAvailable log levels: {', '.join(levels)}")
        new_level = input("Enter new log level: ").strip().upper()

        if new_level in levels:
            self.config["log_level"] = new_level
            save_config(self.config)
            print(f"\033[92m[+]\033[0m Log level updated to {new_level}")
        else:
            print("\033[91m[!]\033[0m Invalid log level.")

    def _update_vpn_dir(self):
        """Update VPN configuration directory"""
        new_dir = input("Enter new VPN config directory path: ").strip()
        if os.path.exists(new_dir):
            self.config["vpn_config_dir"] = new_dir
            save_config(self.config)
            print(f"\033[92m[+]\033[0m VPN config directory updated to {new_dir}")
        else:
            print("\033[91m[!]\033[0m Directory does not exist.")

    def _update_output_dir(self):
        """Update output directory"""
        new_dir = input("Enter new output directory path: ").strip()
        try:
            os.makedirs(new_dir, exist_ok=True)
            self.config["output_dir"] = new_dir
            save_config(self.config)
            print(f"\033[92m[+]\033[0m Output directory updated to {new_dir}")
        except Exception as e:
            print(f"\033[91m[!]\033[0m Failed to create directory: {e}")

    def _reset_config(self):
        """Reset configuration to defaults"""
        confirm = (
            input("Are you sure you want to reset to defaults? (y/N): ").strip().lower()
        )
        if confirm == "y":
            from config.settings import DEFAULT_CONFIG

            self.config = DEFAULT_CONFIG.copy()
            save_config(self.config)
            print("\033[92m[+]\033[0m Configuration reset to defaults.")

    def _system_installation_manager(self):
        """System installation management menu"""
        while True:
            print_clean_menu_header(
                "SYSTEM INSTALLATION MANAGER", "Install Framework System-Wide"
            )

            # Check if already installed
            is_installed = os.path.exists("/opt/leegion-framework") and os.path.exists(
                "/usr/local/bin/leegion"
            )

            if is_installed:
                print("\033[92m✅ Leegion Framework is installed system-wide\033[0m")
                print(f"\033[96mInstallation Path:\033[0m /opt/leegion-framework")
                print(f"\033[96mExecutable:\033[0m /usr/local/bin/leegion")
                print(f"\033[96mUser Config:\033[0m ~/.config/leegion")
                print()
                print("\033[96m1.\033[0m Reinstall Framework")
                print("\033[96m2.\033[0m Uninstall Framework")
                print("\033[96m3.\033[0m View Installation Status")
                print("\033[96m0.\033[0m Back to Settings Menu")
            else:
                print(
                    "\033[91m❌ Leegion Framework is not installed system-wide\033[0m"
                )
                print("\033[93mCurrently running from:\033[0m", os.getcwd())
                print()
                print("\033[96m1.\033[0m Install Framework System-Wide")
                print("\033[96m2.\033[0m Installation Requirements")
                print("\033[96m3.\033[0m Manual Installation Guide")
                print("\033[96m0.\033[0m Back to Settings Menu")

            print(f"\033[96m{'='*65}\033[0m")
            choice = input("\033[93mEnter your choice: \033[0m").strip()

            if choice == "1":
                if is_installed:
                    self._reinstall_framework()
                else:
                    self._install_framework()
            elif choice == "2":
                if is_installed:
                    self._uninstall_framework()
                else:
                    self._show_installation_requirements()
            elif choice == "3":
                if is_installed:
                    self._show_installation_status()
                else:
                    self._show_manual_installation_guide()
            elif choice == "0":
                break
            else:
                print("\033[91m[!]\033[0m Invalid choice. Please try again.")
                input("\n\033[93mPress Enter to continue...\033[0m")

    def _install_framework(self):
        """Install framework system-wide"""
        print("\n\033[93m🚀 SYSTEM-WIDE INSTALLATION\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        # Check if running as root
        if os.geteuid() != 0:
            print("\033[91m❌ Root privileges required for system installation\033[0m")
            print()
            print("\033[96mTo install system-wide, please run:\033[0m")
            print(
                f"  \033[92msudo python3 {os.path.join(os.getcwd(), 'setup.py')}\033[0m"
            )
            print()
            print("\033[96mOr use the quick installer:\033[0m")
            print(f"  \033[92msudo {os.path.join(os.getcwd(), 'install.sh')}\033[0m")
            print()
            print(
                "\033[96mAfter installation, you can run 'leegion' from anywhere!\033[0m"
            )
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        # Confirm installation
        print("\033[96mThis will install Leegion Framework system-wide:\033[0m")
        print("  • Framework files: /opt/leegion-framework/")
        print("  • Global command: /usr/local/bin/leegion")
        print("  • User config: ~/.config/leegion/")
        print()

        confirm = (
            input("\033[93mProceed with installation? (y/N): \033[0m").strip().lower()
        )
        if confirm != "y":
            print("\033[93m[!]\033[0m Installation cancelled.")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        try:
            # Run the setup script
            setup_script = os.path.join(os.getcwd(), "setup.py")

            print("\n\033[96m📦 Running installation script...\033[0m")
            result = subprocess.run(
                [sys.executable, setup_script], capture_output=True, text=True
            )

            if result.returncode == 0:
                print("\033[92m✅ Installation completed successfully!\033[0m")
                print(
                    "\033[96mYou can now run 'leegion' from anywhere on your system.\033[0m"
                )
            else:
                print("\033[91m❌ Installation failed:\033[0m")
                print(result.stderr)

        except Exception as e:
            print(f"\033[91m❌ Installation error: {e}\033[0m")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _reinstall_framework(self):
        """Reinstall the framework"""
        print("\n\033[93m🔄 FRAMEWORK REINSTALLATION\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")

        confirm = (
            input("\033[93mThis will reinstall the framework. Continue? (y/N): \033[0m")
            .strip()
            .lower()
        )
        if confirm != "y":
            print("\033[93m[!]\033[0m Reinstallation cancelled.")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        # Check if running as root
        if os.geteuid() != 0:
            print("\033[91m❌ Root privileges required for reinstallation\033[0m")
            print(
                f"  \033[92msudo python3 {os.path.join(os.getcwd(), 'setup.py')}\033[0m"
            )
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        try:
            setup_script = os.path.join(os.getcwd(), "setup.py")

            print("\n\033[96m📦 Running reinstallation...\033[0m")
            result = subprocess.run(
                [sys.executable, setup_script], capture_output=True, text=True
            )

            if result.returncode == 0:
                print("\033[92m✅ Reinstallation completed successfully!\033[0m")
            else:
                print("\033[91m❌ Reinstallation failed:\033[0m")
                print(result.stderr)

        except Exception as e:
            print(f"\033[91m❌ Reinstallation error: {e}\033[0m")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _uninstall_framework(self):
        """Uninstall the framework"""
        print("\n\033[91m🗑️  FRAMEWORK UNINSTALLATION\033[0m")
        print("\033[91m" + "=" * 50 + "\033[0m")

        print("\033[93m⚠️  This will remove:\033[0m")
        print("  • /opt/leegion-framework/ (framework files)")
        print("  • /usr/local/bin/leegion (global command)")
        print("  • User config will be preserved in ~/.config/leegion/")
        print()

        confirm = (
            input("\033[93mAre you sure you want to uninstall? (y/N): \033[0m")
            .strip()
            .lower()
        )
        if confirm != "y":
            print("\033[93m[!]\033[0m Uninstallation cancelled.")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        # Check if running as root
        if os.geteuid() != 0:
            print("\033[91m❌ Root privileges required for uninstallation\033[0m")
            print("  \033[92msudo /opt/leegion-framework/uninstall.sh\033[0m")
            input("\n\033[93mPress Enter to continue...\033[0m")
            return

        try:
            uninstall_script = "/opt/leegion-framework/uninstall.sh"

            if os.path.exists(uninstall_script):
                print("\n\033[96m🗑️  Running uninstallation script...\033[0m")
                result = subprocess.run(
                    ["/bin/bash", uninstall_script], capture_output=True, text=True
                )

                if result.returncode == 0:
                    print("\033[92m✅ Uninstallation completed successfully!\033[0m")
                    print(
                        "\033[96mUser configuration preserved in ~/.config/leegion/\033[0m"
                    )
                else:
                    print("\033[91m❌ Uninstallation failed:\033[0m")
                    print(result.stderr)
            else:
                print(
                    "\033[91m❌ Uninstaller not found. Manual removal required.\033[0m"
                )

        except Exception as e:
            print(f"\033[91m❌ Uninstallation error: {e}\033[0m")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _show_installation_status(self):
        """Show detailed installation status"""
        print("\n\033[96m📋 INSTALLATION STATUS\033[0m")
        print("\033[96m" + "=" * 40 + "\033[0m")

        # Check various installation components
        checks = [
            ("/opt/leegion-framework", "Framework Directory"),
            ("/usr/local/bin/leegion", "Global Executable"),
            (os.path.expanduser("~/.config/leegion"), "User Config Directory"),
            (os.path.expanduser("~/.config/leegion/config.json"), "User Config File"),
        ]

        for path, description in checks:
            exists = os.path.exists(path)
            status = "\033[92m✅\033[0m" if exists else "\033[91m❌\033[0m"
            print(f"{status} {description}: {path}")

        print()

        # Show version info if installed
        if os.path.exists("/opt/leegion-framework/main.py"):
            try:
                result = subprocess.run(
                    ["/usr/local/bin/leegion", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    print(f"\033[96mVersion:\033[0m {result.stdout.strip()}")
            except (subprocess.CalledProcessError, FileNotFoundError, OSError):
                print("\033[96mVersion:\033[0m Unable to determine")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _show_installation_requirements(self):
        """Show installation requirements"""
        print("\n\033[96m📋 INSTALLATION REQUIREMENTS\033[0m")
        print("\033[96m" + "=" * 50 + "\033[0m")

        print("\033[96m🔧 System Requirements:\033[0m")
        print("  • Linux operating system")
        print("  • Python 3.6 or higher")
        print("  • Root/sudo access for system installation")
        print("  • Internet connection for dependencies")
        print()

        print("\033[96m📦 Dependencies (automatically installed):\033[0m")
        deps = [
            "python3-nmap",
            "requests",
            "colorama",
            "tabulate",
            "pyyaml",
            "dnspython",
            "beautifulsoup4",
            "cryptography",
        ]
        for dep in deps:
            print(f"  • {dep}")

        print()
        print("\033[96m🎯 Installation Commands:\033[0m")
        print("  \033[92m# Quick install\033[0m")
        print(f"  sudo {os.path.join(os.getcwd(), 'install.sh')}")
        print()
        print("  \033[92m# Manual install\033[0m")
        print(f"  sudo python3 {os.path.join(os.getcwd(), 'setup.py')}")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def _show_manual_installation_guide(self):
        """Show manual installation guide"""
        print("\n\033[96m📖 MANUAL INSTALLATION GUIDE\033[0m")
        print("\033[96m" + "=" * 50 + "\033[0m")

        print("\033[96m1. Quick Installation:\033[0m")
        print(f"   sudo {os.path.join(os.getcwd(), 'install.sh')}")
        print()

        print("\033[96m2. Python Setup Script:\033[0m")
        print(f"   sudo python3 {os.path.join(os.getcwd(), 'setup.py')}")
        print()

        print("\033[96m3. Using Makefile:\033[0m")
        print("   make install")
        print()

        print("\033[96m4. After Installation:\033[0m")
        print("   • Run 'leegion' from anywhere")
        print("   • Config files in ~/.config/leegion/")
        print("   • VPN configs in ~/.config/leegion/vpn_configs/")
        print()

        print("\033[96m5. Uninstallation:\033[0m")
        print("   sudo /opt/leegion-framework/uninstall.sh")

        input("\n\033[93mPress Enter to continue...\033[0m")

    def run_cli_loop(self):
        """Main CLI loop with enhanced error handling"""
        try:
            while True:
                self.display_menu()
                choice = input("\033[93mEnter your choice: \033[0m").strip()

                try:
                    if choice == "1":
                        clear_screen()
                        self.modules["vpn"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "2":
                        clear_screen()
                        self.modules["nmap"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "3":
                        clear_screen()
                        self.modules["wpscan"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "4":
                        clear_screen()
                        self.modules["subdomain"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "5":
                        clear_screen()
                        self.modules["dirbrute"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "6":
                        clear_screen()
                        self.modules["ssl"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "7":
                        clear_screen()
                        self.modules["helper"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "8":
                        clear_screen()
                        self.modules["downloader"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "9":
                        clear_screen()
                        self.modules["revshell"].run()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "10":
                        clear_screen()
                        self.report_generator.interactive_report_generation()
                        input("\n\033[93mPress Enter to return to main menu...\033[0m")
                    elif choice == "11":
                        clear_screen()
                        self.handle_settings_menu()
                    elif choice == "0":
                        clear_screen()
                        print(
                            "\033[92m[+]\033[0m Exiting Leegion Framework. Happy Ethical Hacking!"
                        )
                        self.logger.info("Framework shutdown initiated by user")
                        break
                    else:
                        print("\033[91m[!]\033[0m Invalid choice. Please select 0-11.")
                        input("\n\033[93mPress Enter to continue...\033[0m")

                except KeyboardInterrupt:
                    print("\n\033[93m[!]\033[0m Operation interrupted by user.")
                    continue
                except Exception as e:
                    print(f"\033[91m[!]\033[0m An error occurred: {e}")
                    self.logger.error(f"Module execution error: {e}")
                    continue

                # Small delay to prevent rapid menu cycling
                time.sleep(0.5)

        except KeyboardInterrupt:
            handle_keyboard_interrupt()
        except Exception as e:
            print(f"\033[91m[!]\033[0m Critical error: {e}")
            self.logger.critical(f"Critical framework error: {e}")
            sys.exit(1)


def setup_argument_parser():
    """Setup command line argument parsing"""
    parser = argparse.ArgumentParser(
        description="Leegion Framework - Enhanced Cybersecurity Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start interactive mode
  python main.py --module nmap      # Run specific module
  python main.py --config custom.json  # Use custom config
        """,
    )

    parser.add_argument(
        "--config",
        "-c",
        default="config/config.json",
        help="Path to configuration file (default: config/config.json)",
    )

    parser.add_argument(
        "--module",
        "-m",
        choices=[
            "vpn",
            "nmap",
            "wpscan",
            "subdomain",
            "dirbrute",
            "ssl",
            "helper",
            "revshell",
        ],
        help="Run specific module directly",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument("--version", action="version", version="Leegion Framework v2.0")

    return parser


def main():
    """Main entry point for Leegion Framework"""
    try:
        # Load configuration
        config = load_config()

        # Initialize monitoring system
        initialize_monitoring(config)

        # Initialize backup manager
        initialize_backup_manager(config)

        # Create necessary directories
        create_directories_from_config(config)

        # Initialize logger
        logger = setup_logger(config.get("log_level", "INFO"))

        # Display banner
        print_banner()

        # Main application loop
        app = LeegionFramework(config, logger)
        app.run_cli_loop()

    except KeyboardInterrupt:
        print("\n\033[93m[!]\033[0m Framework interrupted by user")
        # Stop monitoring before exit
        monitoring_system = get_monitoring_system()
        if monitoring_system:
            monitoring_system.stop_monitoring()
    except Exception as e:
        print(f"\033[91m[!]\033[0m Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
