#!/usr/bin/env python3
"""
Leegion Framework Manager

This module provides the main management interface for the Leegion Framework,
handling module initialization, configuration, and execution.

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import os
import sys
import shutil
import subprocess
import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict


# Installation configuration
INSTALL_DIR = Path("/opt/leegion-framework")
BIN_DIR = Path("/usr/local/bin")
EXECUTABLE_NAME = "leegion"
USER_CONFIG_DIR = Path.home() / ".config" / "leegion"


# Colors for output
class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"  # No Color


def print_banner():
    """Print installation banner"""
    print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")
    print(f"{Colors.BLUE}  LEEGION FRAMEWORK MANAGER{Colors.NC}")
    print(f"{Colors.BLUE}  Enhanced Cybersecurity Toolkit{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.NC}")


def print_info(message: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.NC}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.NC}")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}❌ {message}{Colors.NC}")


def print_step(message: str):
    """Print step message"""
    print(f"{Colors.CYAN}🔧 {message}{Colors.NC}")


def check_root():
    """Check if running with appropriate permissions"""
    if os.geteuid() != 0:
        print_error("This operation requires root privileges.")
        print_info("Please run with sudo:")
        print(
            f"sudo python3 {sys.argv[0]} " f"{sys.argv[1] if len(sys.argv) > 1 else ''}"
        )
        sys.exit(1)


def check_apt():
    """Check if apt is available"""
    if not shutil.which("apt"):
        print_error(
            "'apt' package manager not found. "
            "This manager currently supports Debian-based systems."
        )
        sys.exit(1)


def check_python():
    """Check Python availability"""
    if not shutil.which("python3"):
        print_error("Python 3 is required but not installed")
        print_info("Installing Python 3...")
        try:
            subprocess.run(["apt", "update"], check=True, capture_output=True)
            subprocess.run(
                ["apt", "install", "-y", "python3", "python3-pip", "python3-venv"],
                check=True,
            )
            print_success("Python 3 installed successfully")
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to install Python 3: {e}")
            sys.exit(1)


def install_dependencies():
    """Install required system dependencies"""
    print_step("Installing system dependencies...")

    dependencies = ["python3", "python3-venv", "python3-pip", "nmap", "curl", "git"]

    try:
        # Update package list
        subprocess.run(["apt", "update"], check=True, capture_output=True)

        # Install dependencies
        subprocess.run(["apt", "install", "-y"] + dependencies, check=True)
        print_success("System dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print_warning(f"Could not install some system dependencies: {e}")
        print_info("You may need to install them manually")


def install_python_packages():
    """Create venv and install required Python packages inside it"""
    print_step("Setting up Python virtual environment...")
    venv_path = INSTALL_DIR / "venv"
    if not venv_path.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)

    pip_executable = venv_path / "bin" / "pip"
    
    # Install from pyproject.toml to ensure all dependencies are included
    print_step("Installing Python packages from pyproject.toml...")
    subprocess.run([str(pip_executable), "install", "--upgrade", "pip"], check=True)
    
    # Install the project in editable mode with all dependencies
    subprocess.run([str(pip_executable), "install", "-e", "."], check=True)
    
    # Also install dev dependencies for testing
    subprocess.run([str(pip_executable), "install", "-e", ".[dev]"], check=True)
    
    print_success("Python packages installed successfully in venv")


def copy_framework_files():
    """Copy framework files to installation directory"""
    print_step(f"Installing framework to {INSTALL_DIR}...")

    # Create installation directory
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    # Files and directories to copy
    items_to_copy = [
        "main.py",
        "core/",
        "modules/",
        "config/",
        "reports/",
        "tests/",
        "wordlists/",
        "screenshots/",
        "pyproject.toml",
        "Makefile",
    ]

    current_dir = Path.cwd()

    for item in items_to_copy:
        source = current_dir / item
        dest = INSTALL_DIR / item

        if source.exists():
            if source.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(source, dest)
            else:
                shutil.copy2(source, dest)
            print(f"  ✓ Copied {item}")
        else:
            print(f"  ⚠️  Warning: {item} not found")

    # Create necessary directories
    directories = ["logs", "vpn_configs"]
    for directory in directories:
        dir_path = INSTALL_DIR / directory
        dir_path.mkdir(exist_ok=True)
        print(f"  ✓ Created {directory}/")


def create_executable():
    """Create the main executable script"""
    print_step(f"Creating executable: {EXECUTABLE_NAME}")

    executable_content = f"""#!/bin/bash
# Leegion Framework Launcher
# This script launches the Leegion Framework from anywhere

FRAMEWORK_DIR="{INSTALL_DIR}"
VENV_PYTHON="$FRAMEWORK_DIR/venv/bin/python"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚡ Re-running with sudo to get necessary permissions..."
    exec sudo "$0" "$@"
fi

cd "$FRAMEWORK_DIR" || {{
    echo "❌ Error: Framework not found at $FRAMEWORK_DIR"
    echo "Please reinstall the Leegion Framework"
    exit 1
}}

if [ ! -f "main.py" ]; then
    echo "❌ Error: main.py not found in $FRAMEWORK_DIR"
    echo "Please reinstall the Leegion Framework"
    exit 1
fi

if [ ! -x "$VENV_PYTHON" ]; then
    echo "❌ Error: Python virtual environment not found or broken"
    echo "Please reinstall the Leegion Framework"
    exit 1
fi

"$VENV_PYTHON" main.py "$@"
"""

    executable_path = BIN_DIR / EXECUTABLE_NAME

    with open(executable_path, "w") as f:
        f.write(executable_content)

    os.chmod(executable_path, 0o755)
    print(f"  ✓ Created {executable_path}")


def create_user_config():
    """Create user configuration directory"""
    print_step("Setting up user configuration...")

    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # Create default config if it doesn't exist
    config_file = USER_CONFIG_DIR / "config.json"
    if not config_file.exists():
        default_config = {
            "log_level": "INFO",
            "vpn_config_dir": str(USER_CONFIG_DIR / "vpn_configs"),
            "output_dir": str(USER_CONFIG_DIR / "reports"),
            "database_path": str(USER_CONFIG_DIR / "leegion.db"),
        }
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=4)

    # Create user directories
    user_dirs = ["vpn_configs", "reports", "logs"]
    for directory in user_dirs:
        (USER_CONFIG_DIR / directory).mkdir(exist_ok=True)

    print(f"  ✓ Configuration directory: {USER_CONFIG_DIR}")


def check_installation() -> Dict[str, Any]:
    """Check installation status"""
    print_step("Checking installation status...")

    found_components = []
    missing_components = []

    if INSTALL_DIR.exists():
        found_components.append(f"Framework directory: {INSTALL_DIR}")
    else:
        missing_components.append(f"Framework directory: {INSTALL_DIR}")

    if (BIN_DIR / EXECUTABLE_NAME).exists():
        found_components.append(f"Executable: {BIN_DIR}/{EXECUTABLE_NAME}")
    else:
        missing_components.append(f"Executable: {BIN_DIR}/{EXECUTABLE_NAME}")

    if USER_CONFIG_DIR.exists():
        found_components.append(f"User config: {USER_CONFIG_DIR}")
    else:
        missing_components.append(f"User config: {USER_CONFIG_DIR}")

    print("Installation Status:")
    if found_components:
        print(f"{Colors.GREEN}Installed components:{Colors.NC}")
        for component in found_components:
            print(f"  {Colors.GREEN}✓ {component}{Colors.NC}")

    if missing_components:
        print(f"{Colors.RED}Missing components:{Colors.NC}")
        for component in missing_components:
            print(f"  {Colors.RED}✗ {component}{Colors.NC}")

    if not missing_components:
        print_success("Leegion Framework is fully installed")
        return {
            "status": "installed",
            "found": found_components,
            "missing": missing_components,
        }
    elif not found_components:
        print_warning("Leegion Framework is not installed")
        return {
            "status": "not_installed",
            "found": found_components,
            "missing": missing_components,
        }
    else:
        print_warning("Leegion Framework is partially installed")
        return {
            "status": "partial",
            "found": found_components,
            "missing": missing_components,
        }


def stop_running_processes():
    """Stop any running Leegion processes"""
    print_step("Stopping any running Leegion processes...")

    try:
        # Check for running processes - be more specific to avoid killing the manager
        result = subprocess.run(
            ["pgrep", "-f", "leegion main.py"], capture_output=True, text=True
        )
        if result.returncode == 0:
            print_warning("Found running Leegion processes. Stopping them...")
            subprocess.run(["pkill", "-f", "leegion main.py"], check=False)
            time.sleep(2)

            # Force kill if still running
            result = subprocess.run(
                ["pgrep", "-f", "leegion main.py"], capture_output=True, text=True
            )
            if result.returncode == 0:
                print_warning("Force stopping remaining processes...")
                subprocess.run(["pkill", "-9", "-f", "leegion main.py"], check=False)

            print_success("All Leegion processes stopped")
        else:
            print_info("No running Leegion processes found")
    except Exception as e:
        print_warning(f"Could not check for running processes: {e}")


def cleanup_cache():
    """Clean up cache and temporary files"""
    print_step("Cleaning up cache and temporary files...")

    try:
        # Remove Python cache files
        subprocess.run(
            [
                "find",
                str(Path.home()),
                "-name",
                "__pycache__",
                "-type",
                "d",
                "-exec",
                "rm",
                "-rf",
                "{}",
                "+",
            ],
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["find", str(Path.home()), "-name", "*.pyc", "-delete"],
            capture_output=True,
            check=False,
        )

        # Remove temporary files
        for temp_file in Path("/tmp").glob("leegion_*"):
            temp_file.unlink(missing_ok=True)

        print_success("Cache files cleaned up")
    except Exception as e:
        print_warning(f"Could not clean all cache files: {e}")


def run_tests():
    """Run framework tests"""
    print_step("Running framework tests...")

    try:
        # Test framework import
        print("🧪 Testing framework...")
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.append('.'); import main; "
                "print('✅ Framework imports successfully')",
            ],
            check=True,
        )

        # Check if framework is installed and use its virtual environment
        if INSTALL_DIR.exists():
            venv_python = INSTALL_DIR / "venv" / "bin" / "python"
            if venv_python.exists():
                print("🧪 Running unit tests using framework's virtual environment...")
                subprocess.run(
                    [str(venv_python), "-m", "pytest", "tests/", "-v", "--tb=short"],
                    check=True,
                )
            else:
                print_warning(
                    "Framework virtual environment not found, "
                    "trying system pytest..."
                )
                subprocess.run(
                    [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
                    check=True,
                )
        else:
            print("🧪 Running unit tests using system Python...")
            # Try to install pytest if not available
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--user", "pytest"],
                    check=True,
                )
            except subprocess.CalledProcessError:
                print_warning("Could not install pytest, skipping tests")
                return

            subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
                check=True,
            )

        print_success("All tests passed!")
    except subprocess.CalledProcessError as e:
        print_error(f"Tests failed: {e}")
        sys.exit(1)


def install_framework():
    """Install the framework"""
    print_step("Installing Leegion Framework...")

    try:
        # Check prerequisites
        check_apt()
        check_python()

        # Install system dependencies
        install_dependencies()

        # Install Python packages in venv
        install_python_packages()

        # Copy framework files
        copy_framework_files()

        # Create executable
        create_executable()

        # Set up user config
        create_user_config()

        print_success("Installation completed!")
        print_info("You can now run 'leegion' from anywhere on your system")

    except Exception as e:
        print_error(f"Installation failed: {e}")
        sys.exit(1)


def uninstall_framework():
    """Uninstall the framework"""
    print_step("Uninstalling Leegion Framework...")

    try:
        # Stop running processes
        stop_running_processes()

        # Remove framework files
        if INSTALL_DIR.exists():
            print_info(f"Removing {INSTALL_DIR}...")
            shutil.rmtree(INSTALL_DIR)
            print_success("Framework directory removed")

        # Remove executable
        executable_path = BIN_DIR / EXECUTABLE_NAME
        if executable_path.exists():
            print_info(f"Removing {executable_path}...")
            executable_path.unlink()
            print_success("Executable removed")

        # Remove user config (ask first)
        if USER_CONFIG_DIR.exists():
            response = input(f"Remove user configuration ({USER_CONFIG_DIR})? (y/N): ")
            if response.lower() in ["y", "yes"]:
                print_info(f"Removing {USER_CONFIG_DIR}...")
                shutil.rmtree(USER_CONFIG_DIR)
                print_success("User configuration removed")
            else:
                print_info("User configuration preserved")

        # Clean up cache
        cleanup_cache()

        print_success("Uninstallation completed!")

    except Exception as e:
        print_error(f"Uninstallation failed: {e}")
        sys.exit(1)


def update_framework():
    """Update the framework"""
    print_step("Updating Leegion Framework...")

    if not INSTALL_DIR.exists():
        print_error("Framework not installed. Please install first.")
        sys.exit(1)

    try:
        # Backup current installation
        backup_dir = Path(f"/tmp/leegion-backup-{int(time.time())}")
        print_info(f"Creating backup at {backup_dir}...")
        shutil.copytree(INSTALL_DIR, backup_dir)

        # Stop processes
        stop_running_processes()

        # Reinstall
        install_framework()

        print_success("Update completed!")
        print_info(f"Backup saved at: {backup_dir}")

    except Exception as e:
        print_error(f"Update failed: {e}")
        sys.exit(1)


def show_interactive_menu():
    """Show interactive menu"""
    while True:
        print_banner()

        # Check installation status
        status_info = check_installation()
        print()

        print(f"{Colors.CYAN}Leegion Framework Management Menu{Colors.NC}")
        print("=" * 42)
        print()

        # Show current status
        if status_info["status"] == "installed":
            print(f"{Colors.GREEN}✓ Framework Status: INSTALLED{Colors.NC}")
        elif status_info["status"] == "not_installed":
            print(f"{Colors.RED}✗ Framework Status: NOT INSTALLED{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}⚠ Framework Status: PARTIALLY INSTALLED{Colors.NC}")
        print()

        print("Available Actions:")
        print()
        print(f"{Colors.BLUE}1){Colors.NC} Install Framework")
        print(f"{Colors.BLUE}2){Colors.NC} Uninstall Framework")
        print(f"{Colors.BLUE}3){Colors.NC} Reinstall Framework")
        print(f"{Colors.BLUE}4){Colors.NC} Check Status")
        print(f"{Colors.BLUE}5){Colors.NC} Update Framework")
        print(f"{Colors.BLUE}6){Colors.NC} Clean Cache")
        print(f"{Colors.BLUE}7){Colors.NC} Run Tests")
        print(f"{Colors.BLUE}8){Colors.NC} Show Help")
        print(f"{Colors.BLUE}9){Colors.NC} Exit")
        print()

        try:
            choice = input("Select an option (1-9): ").strip()

            if choice == "1":
                print()
                install_framework()
                input("\nPress Enter to continue...")
            elif choice == "2":
                print()
                uninstall_framework()
                input("\nPress Enter to continue...")
            elif choice == "3":
                print()
                uninstall_framework()
                print()
                install_framework()
                input("\nPress Enter to continue...")
            elif choice == "4":
                print()
                check_installation()
                input("\nPress Enter to continue...")
            elif choice == "5":
                print()
                if status_info["status"] == "installed":
                    update_framework()
                else:
                    print_error("Framework not installed. Please install first.")
                input("\nPress Enter to continue...")
            elif choice == "6":
                print()
                cleanup_cache()
                input("\nPress Enter to continue...")
            elif choice == "7":
                print()
                run_tests()
                input("\nPress Enter to continue...")
            elif choice == "8":
                print()
                show_help()
                input("\nPress Enter to continue...")
            elif choice == "9":
                print()
                print_info("Exiting...")
                sys.exit(0)
            else:
                print()
                print_error("Invalid option. Please select 1-9.")
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n")
            print_info("Exiting...")
            sys.exit(0)


def show_help():
    """Show help information"""
    print("Leegion Framework Manager - Help")
    print("=" * 35)
    print()
    print("Commands:")
    print("  install     Install Leegion Framework")
    print("  uninstall   Uninstall Leegion Framework")
    print("  reinstall   Reinstall Leegion Framework")
    print("  status      Show installation status")
    print("  update      Update framework")
    print("  clean       Clean cache and temporary files")
    print("  test        Run framework tests")
    print("  menu        Show interactive menu")
    print("  help        Show this help message")
    print()
    print("Examples:")
    print("  python3 leegion_manager.py install")
    print("  python3 leegion_manager.py status")
    print("  python3 leegion_manager.py menu")
    print()
    print("Note: Install, uninstall, and update commands require root privileges.")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Leegion Framework Manager - Installation and management tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 leegion_manager.py install     # Install framework
  python3 leegion_manager.py status      # Check status
  python3 leegion_manager.py menu        # Interactive menu
        """,
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "install",
            "uninstall",
            "reinstall",
            "status",
            "update",
            "clean",
            "test",
            "menu",
            "help",
        ],
        help="Command to execute",
    )

    parser.add_argument(
        "--force", action="store_true", help="Force operation without confirmation"
    )

    args = parser.parse_args()

    # If no command provided, show interactive menu
    if not args.command:
        show_interactive_menu()
        return

    # Handle commands
    if args.command == "install":
        check_root()
        install_framework()
    elif args.command == "uninstall":
        check_root()
        uninstall_framework()
    elif args.command == "reinstall":
        check_root()
        uninstall_framework()
        print()
        install_framework()
    elif args.command == "status":
        check_installation()
    elif args.command == "update":
        check_root()
        update_framework()
    elif args.command == "clean":
        check_root()
        cleanup_cache()
    elif args.command == "test":
        run_tests()
    elif args.command == "menu":
        show_interactive_menu()
    elif args.command == "help":
        show_help()


if __name__ == "__main__":
    main()
