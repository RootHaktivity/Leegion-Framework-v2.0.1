"""
Banner and branding for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import random
from typing import List


def print_banner():
    """Print the main framework banner"""
    clear_screen()

    # Color variations
    colors = [
        "\033[96m",  # Cyan
        "\033[92m",  # Green
        "\033[94m",  # Blue
        "\033[95m",  # Magenta
    ]

    # Select random color
    color = random.choice(colors)
    reset = "\033[0m"

    print(f"{color}")
    print(
        r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║   _      _____  _____   ____  ___  _   _ ___ ___  _   _      ║
    ║  | |    | ____|| ____| |  _ \|_ _| \ | |_ _|_ _| \ | |      ║
    ║  | |    |  _|  |  _|   | |_) || |  \| || | | | |  \| |      ║
    ║  | |___ | |___ | |___  |  __/ | | |\  || | | | | |\  |      ║
    ║  |_____| |_____||_____| |_|   |___|_| \_|___|___|_| \_|      ║
    ║                                                              ║
    ║              ENHANCED CYBERSECURITY FRAMEWORK               ║
    ║                        Version 2.0                          ║
    ║                                                              ║
    ║                    Created by Leegion                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    )
    print(f"{reset}")

    # Framework info
    print(f"\033[96m{'='*65}\033[0m")
    print("\033[96m" + "Framework Info".center(65) + "\033[0m")
    print("\033[96m" + "=" * 65 + "\033[0m")
    print("\033[92m[+]\033[0m Leegion Framework v2.0 - Enhanced Cybersecurity Toolkit")
    print("\033[92m[+]\033[0m Designed for Ethical Hacking & CTF Competitions")
    print("\033[92m[+]\033[0m Built for Linux Terminals | Python Framework")
    print("\033[96m" + "=" * 65 + "\033[0m")

    # Feature highlights
    features = [
        "Advanced VPN Management with Status Monitoring",
        "Network Scanning with Nmap Integration",
        "WordPress Security Assessment",
        "Subdomain Enumeration & Discovery",
        "Directory Bruteforce & Web Fuzzing",
        "SSL/TLS Security Analysis",
        "Comprehensive Logging & Reporting",
        "Modular Architecture for Easy Extension",
    ]

    print("\033[93m" + "Key Features".center(65) + "\033[0m")
    print("\033[93m" + "-" * 65 + "\033[0m")
    for i, feature in enumerate(features, 1):
        print(f"\033[94m{i:2d}.\033[0m {feature}")

    print(f"\033[96m{'='*65}\033[0m")

    # Security disclaimer
    print_security_disclaimer()

    # Learning resources for beginners
    print_learning_resources()


def print_security_disclaimer():
    """Print security and legal disclaimer"""
    disclaimer = """
    ⚠️  SECURITY & LEGAL DISCLAIMER ⚠️

    This tool is designed for:
    • Authorized penetration testing
    • Educational purposes and learning
    • CTF competitions and challenges
    • Security research with proper permissions

    ❌ DO NOT USE FOR:
    • Unauthorized access to systems
    • Illegal activities or malicious purposes
    • Testing systems without explicit permission

    By using this framework, you agree to use it responsibly
    and in compliance with all applicable laws and regulations.
    """

    print("\033[91m" + disclaimer + "\033[0m")
    print("\033[96m" + "=" * 65 + "\033[0m")


def print_learning_resources():
    """Print learning resources for beginners"""
    print("\n\033[96m" + "=" * 65 + "\033[0m")
    print("\033[96m" + "🎓 LEARNING RESOURCES FOR BEGINNERS".center(65) + "\033[0m")
    print("\033[96m" + "=" * 65 + "\033[0m")
    print(
        f"\033[92m🌟 TryHackMe.com\033[0m - Interactive cybersecurity learning platform"
    )
    print("   • Hands-on labs and guided learning paths")
    print("   • Practice the tools and techniques in this framework")
    print("   • Build skills from beginner to advanced levels")
    print(
        f"\n\033[93m💡 PRO TIP:\033[0m Start with TryHackMe's 'Complete Beginner' path"
    )
    print("   then use this framework to practice what you learn!")
    print(f"\033[96m{'='*65}\033[0m")


def print_module_header(module_name: str, description: str = ""):
    """
    Print header for individual modules

    Args:
        module_name: Name of the module
        description: Optional description
    """
    header_width = 60

    print(f"\n\033[94m{'='*header_width}\033[0m")
    print(f"\033[94m{module_name.upper().center(header_width)}\033[0m")
    if description:
        print(f"\033[96m{description.center(header_width)}\033[0m")
    print(f"\033[94m{'='*header_width}\033[0m")


def print_section_header(section_name: str):
    """
    Print section header within modules

    Args:
        section_name: Name of the section
    """
    print(f"\n\033[93m--- {section_name} ---\033[0m")


def print_status_message(message: str, status: str = "info"):
    """
    Print formatted status message

    Args:
        message: Message to display
        status: Type of status (info, success, warning, error)
    """
    colors = {
        "info": "\033[96m[i]\033[0m",
        "success": "\033[92m[+]\033[0m",
        "warning": "\033[93m[!]\033[0m",
        "error": "\033[91m[!]\033[0m",
    }

    prefix = colors.get(status, "\033[96m[i]\033[0m")
    print(f"{prefix} {message}")


def print_results_table(
    headers: List[str], rows: List[List[str]], title: str = "Results"
):
    """
    Print formatted results table

    Args:
        headers: Table column headers
        rows: Table data rows
        title: Table title
    """
    try:
        from tabulate import tabulate

        print(f"\n\033[93m{title}\033[0m")
        print(f"\033[93m{'-'*len(title)}\033[0m")

        if rows:
            table = tabulate(rows, headers=headers, tablefmt="grid")
            print(table)
        else:
            print("\033[91mNo results to display\033[0m")

    except ImportError:
        # Fallback to simple formatting if tabulate not available
        print(f"\n\033[93m{title}\033[0m")
        print(f"\033[93m{'-'*len(title)}\033[0m")

        # Print headers
        header_line = " | ".join(f"{h:15}" for h in headers)
        print(header_line)
        print("-" * len(header_line))

        # Print rows
        for row in rows:
            row_line = " | ".join(f"{str(cell):15}" for cell in row)
            print(row_line)


def print_ascii_art_random():
    """Print random ASCII art for variety"""
    art_options = [
        r"""
        ⚡ SCANNING IN PROGRESS ⚡
        """,
        r"""
        🔍 RECONNAISSANCE MODE 🔍
        """,
        r"""
        🛡️  SECURITY ANALYSIS 🛡️
        """,
        r"""
        🎯 TARGET ACQUIRED 🎯
        """,
    ]

    selected_art = random.choice(art_options)
    print(f"\033[95m{selected_art}\033[0m")


def print_completion_banner(module_name: str, duration: float = 0):
    """
    Print completion banner for modules

    Args:
        module_name: Name of completed module
        duration: Execution duration in seconds
    """
    print(f"\n\033[92m{'='*50}\033[0m")
    print(f"\033[92m{f'{module_name} COMPLETED'.center(50)}\033[0m")
    if duration > 0:
        print(f"\033[92m{f'Execution Time: {duration:.2f} seconds'.center(50)}\033[0m")
    print(f"\033[92m{'='*50}\033[0m")


def clear_screen():
    """Clear the terminal screen"""
    import os
    import sys

    # Force clear the screen using multiple methods
    print("\033[2J\033[H", end="")  # ANSI escape sequence
    sys.stdout.flush()
    if os.name == "posix":
        os.system("clear")
    else:
        os.system("cls")
    # Add extra blank lines to ensure clean display
    print("\n" * 3, end="")
    sys.stdout.flush()


def print_clean_menu_header(title: str, subtitle: str = ""):
    """Print a clean menu header after clearing screen"""
    clear_screen()
    print(f"\033[96m{'='*65}\033[0m")
    print(f"\033[96m{title.center(65)}\033[0m")
    if subtitle:
        print(f"\033[94m{subtitle.center(65)}\033[0m")
    print(f"\033[96m{'='*65}\033[0m")
