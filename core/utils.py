"""
Utility functions for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import os
import sys
import subprocess
import platform
import random
import string
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logger import setup_logger

# Required packages for the framework
REQUIRED_PACKAGES = ["python-nmap", "requests", "colorama", "tabulate", "pyyaml"]

# Optional packages that enhance functionality
OPTIONAL_PACKAGES = ["python-openvpn", "dnspython", "cryptography", "beautifulsoup4"]


def install_package(package: str) -> bool:
    """
    Install a Python package using multiple methods

    Args:
        package: Package name to install

    Returns:
        True if successful, False otherwise
    """
    print(f"\033[96m[+]\033[0m Installing {package}...")

    # Try different installation methods
    install_methods = [
        # Method 1: pip install with --user flag
        [sys.executable, "-m", "pip", "install", "--user", package],
        # Method 2: pip3 install with --user flag
        ["pip3", "install", "--user", package],
        # Method 3: apt install for common packages on Debian/Ubuntu/Kali
        (
            ["apt", "install", "-y", f"python3-{package.replace('-', '')}"]
            if package in ["python-nmap", "requests", "pyyaml"]
            else None
        ),
        # Method 4: regular pip install
        [sys.executable, "-m", "pip", "install", package],
    ]

    # Filter out None methods
    install_methods = [method for method in install_methods if method is not None]

    for method in install_methods:
        try:
            subprocess.check_call(
                method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            print(f"\033[92m[+]\033[0m {package} installed successfully")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    # If all methods fail, provide helpful error message
    print(f"\033[91m[!]\033[0m Failed to install {package} using automated methods")
    print(f"\033[93m[!]\033[0m Manual installation options:")
    print(f"    pip3 install --user {package}")
    print(f"    sudo pip3 install {package}")
    if package == "python-nmap":
        print(f"    sudo apt install python3-nmap")
    elif package == "pyyaml":
        print(f"    sudo apt install python3-yaml")
    elif package == "requests":
        print(f"    sudo apt install python3-requests")
    return False


def check_package_installed(package: str) -> bool:
    """
    Check if a package is installed

    Args:
        package: Package name to check

    Returns:
        True if installed, False otherwise
    """
    # Map of package names to their import names
    package_map = {
        "python-nmap": "nmap",
        "pyyaml": "yaml",
        "beautifulsoup4": "bs4",
        "python-openvpn": "openvpn",
    }

    # Get the correct import name
    import_name = package_map.get(package, package.replace("-", "_"))

    try:
        __import__(import_name)
        return True
    except ImportError:
        # Try alternative import names
        alternatives = {
            "nmap": ["python_nmap"],
            "yaml": ["PyYAML", "pyyaml"],
            "bs4": ["beautifulsoup4"],
        }

        if import_name in alternatives:
            for alt in alternatives[import_name]:
                try:
                    __import__(alt)
                    return True
                except ImportError:
                    continue

        return False


def check_and_install_packages() -> None:
    """Check and install required packages"""
    print("\033[96m[+]\033[0m Checking required packages...")

    missing_required = []
    missing_optional = []
    failed_installs = []

    # Check required packages
    for package in REQUIRED_PACKAGES:
        if not check_package_installed(package):
            missing_required.append(package)

    # Check optional packages
    for package in OPTIONAL_PACKAGES:
        if not check_package_installed(package):
            missing_optional.append(package)

    # Install missing required packages
    if missing_required:
        print(
            f"\033[93m[!]\033[0m Missing required packages: {', '.join(missing_required)}"
        )
        for package in missing_required:
            if not install_package(package):
                failed_installs.append(package)

    # Handle failed installations gracefully
    if failed_installs:
        print(
            f"\033[91m[!]\033[0m Failed to auto-install: {', '.join(failed_installs)}"
        )
        print(f"\033[93m[!]\033[0m Framework will continue with limited functionality")
        print(f"\033[96m[i]\033[0m To install manually on Kali Linux:")
        for package in failed_installs:
            if package == "python-nmap":
                print(f"    sudo apt update && sudo apt install python3-nmap")
            elif package == "pyyaml":
                print(f"    sudo apt install python3-yaml")
            elif package == "requests":
                print(f"    sudo apt install python3-requests")
            else:
                print(f"    pip3 install --user {package}")

    # Inform about missing optional packages
    if missing_optional:
        print(
            f"\033[93m[!]\033[0m Optional packages not installed: {', '.join(missing_optional)}"
        )
        print(f"\033[96m[i]\033[0m Some features may be limited without these packages")

    print("\033[92m[+]\033[0m Package check completed")


def check_external_tools() -> Dict[str, bool]:
    """
    Check availability of external tools

    Returns:
        Dictionary with tool names and availability status
    """
    tools = {
        "nmap": "nmap",
        "wpscan": "wpscan",
        "dirb": "dirb",
        "nikto": "nikto",
        "subfinder": "subfinder",
        "gobuster": "gobuster",
        "openvpn": "openvpn",
        "curl": "curl",
        "dig": "dig",
        "nslookup": "nslookup",
    }

    availability = {}

    for tool_name, command in tools.items():
        try:
            result = subprocess.run(
                ["which", command], capture_output=True, text=True, timeout=5
            )
            availability[tool_name] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            availability[tool_name] = False

    return availability


def print_tool_availability():
    """Print the availability status of external tools"""
    print("\n\033[96m[+]\033[0m Checking external tool availability...")
    tools = check_external_tools()

    for tool, available in tools.items():
        status = "\033[92m✓\033[0m" if available else "\033[91m✗\033[0m"
        print(f"  {tool}: {status}")

    missing_tools = [tool for tool, available in tools.items() if not available]
    if missing_tools:
        print(f"\n\033[93m[!]\033[0m Missing tools: {', '.join(missing_tools)}")
        print(f"\033[96m[i]\033[0m Install missing tools for full functionality")


def handle_keyboard_interrupt():
    """Handle Ctrl+C gracefully"""
    print("\n\033[93m[!]\033[0m Keyboard interrupt received")
    print("\033[92m[+]\033[0m Shutting down gracefully...")
    sys.exit(0)


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format

    Args:
        ip: IP address string to validate

    Returns:
        True if valid, False otherwise
    """
    import re

    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(pattern, ip))


def validate_url(url: str) -> bool:
    """
    Validate URL format

    Args:
        url: URL string to validate

    Returns:
        True if valid, False otherwise
    """
    import re

    pattern = r"^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?$"
    return bool(re.match(pattern, url))


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format

    Args:
        domain: Domain string to validate

    Returns:
        True if valid, False otherwise
    """
    import re

    # Require at least one dot in the domain
    domain_pattern = (
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(re.match(domain_pattern, domain))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing/replacing invalid characters

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    import re

    # Replace invalid characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]

    return sanitized or "unnamed_file"


def create_backup(file_path: str) -> Optional[str]:
    """
    Create a backup of an existing file

    Args:
        file_path: Path to file to backup

    Returns:
        Path to backup file or None if failed
    """
    if not os.path.exists(file_path):
        return None

    try:
        import shutil

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.backup_{timestamp}"
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        print(f"\033[91m[!]\033[0m Failed to create backup: {e}")
        return None


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human readable format

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    value = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human readable format

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.0f}s"
    else:
        hours = int(seconds // 3600)
        remaining_minutes = int((seconds % 3600) // 60)
        return f"{hours}h {remaining_minutes}m"


def get_system_info() -> Dict[str, str]:
    """
    Get basic system information

    Returns:
        Dictionary with system information
    """
    import platform

    info = {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }

    return info


def check_internet_connectivity(
    host: str = "8.8.8.8", port: int = 53, timeout: int = 3
) -> bool:
    """
    Check internet connectivity by attempting to connect to a host

    Args:
        host: Host to connect to (default: Google DNS)
        port: Port to connect to
        timeout: Connection timeout in seconds

    Returns:
        True if connected, False otherwise
    """
    import socket

    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False


def run_command_with_timeout(command: List[str], timeout: int = 30) -> Dict[str, Any]:
    """
    Run a command with timeout and capture output

    Args:
        command: Command and arguments as list
        timeout: Timeout in seconds

    Returns:
        Dictionary with returncode, stdout, stderr, and execution time
    """
    start_time = time.time()

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )

        execution_time = time.time() - start_time

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "execution_time": execution_time,
            "timeout": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out",
            "execution_time": timeout,
            "timeout": True,
        }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "execution_time": time.time() - start_time,
            "timeout": False,
        }


class ProgressBar:
    """Simple progress bar for long-running operations"""

    def __init__(self, total: float, prefix: str = "Progress", length: int = 40):
        self.total = int(total)
        self.prefix = prefix
        self.length = length
        self.current = 0

    def update(self, increment: int = 1):
        """Update progress bar"""
        self.current += increment
        if self.current > self.total:
            self.current = self.total

        percent = (self.current / self.total) * 100
        filled_length = int(self.length * self.current // self.total)

        bar = "█" * filled_length + "-" * (self.length - filled_length)
        print(
            f"\r\033[96m{self.prefix}\033[0m |{bar}| {self.current}/{self.total} ({percent:.1f}%)",
            end="",
            flush=True,
        )

        if self.current == self.total:
            print()  # New line when complete

    def finish(self):
        """Complete the progress bar"""
        self.current = self.total
        self.update(0)
