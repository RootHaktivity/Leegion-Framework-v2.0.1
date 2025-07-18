"""
Base module for Leegion Framework
Provides common functionality for all modules

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

import core.logger
import core.monitoring
import core.security
import core.utils


class BaseModule(ABC):
    """Abstract base class for all framework modules"""

    def __init__(self, config: Dict[str, Any], module_name: str):
        self.config = config
        self.module_name = module_name
        self.logger = core.logger.setup_logger(config.get("log_level", "INFO"))
        self.results: List[Dict[str, Any]] = []
        self.session_data: Dict[str, Any] = {}

    @abstractmethod
    def run(self) -> None:
        """Main execution method - must be implemented by subclasses"""
        pass

    def validate_input(self, input_value: str, input_type: str = "general") -> bool:
        """
        Validate user input based on type with enhanced security checks

        Args:
            input_value: The input to validate
            input_type: Type of input (ip, url, domain, port, etc.)

        Returns:
            True if valid, False otherwise
        """
        try:
            # Use enhanced security validation
            result = core.security.validate_input_security(input_value, input_type)

            if not result["valid"]:
                self.print_error(f"Security validation failed: {result['reason']}")
                return False

            # Additional type-specific validation
            if input_type == "ip":
                return self._validate_ip(input_value)
            elif input_type == "url":
                return self._validate_url(input_value)
            elif input_type == "domain":
                return self._validate_domain(input_value)
            elif input_type == "port":
                return self._validate_port(input_value)
            elif input_type == "file_path":
                return self._validate_file_path(input_value)

            return True

        except ImportError:
            # Fallback to original validation if security module not available
            if not input_value or not input_value.strip():
                self.print_error("Input cannot be empty")
                return False

            input_value = input_value.strip()

            if input_type == "ip":
                return self._validate_ip(input_value)
            elif input_type == "url":
                return self._validate_url(input_value)
            elif input_type == "domain":
                return self._validate_domain(input_value)
            elif input_type == "port":
                return self._validate_port(input_value)
            elif input_type == "file_path":
                return self._validate_file_path(input_value)

            return True

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import re

        ip_pattern = (
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        if not re.match(ip_pattern, ip):
            self.print_error(f"Invalid IP address format: {ip}")
            return False
        return True

    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        import re

        url_pattern = (
            r"^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*)?"
            r"(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?$"
        )
        if not re.match(url_pattern, url):
            self.print_error(f"Invalid URL format: {url}")
            return False
        return True

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        import re

        domain_pattern = (
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )
        if not re.match(domain_pattern, domain):
            self.print_error(f"Invalid domain format: {domain}")
            return False
        return True

    def _validate_port(self, port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                self.print_error(f"Port must be between 1 and 65535: {port}")
                return False
            return True
        except ValueError:
            self.print_error(f"Invalid port number: {port}")
            return False

    def _validate_file_path(self, path: str) -> bool:
        """Validate file path exists"""
        import os

        if not os.path.exists(path):
            self.print_error(f"File or directory does not exist: {path}")
            return False
        return True

    def print_success(self, message: str) -> None:
        """Print success message with formatting"""
        if self.config.get("colored_output", True):
            print(f"\033[92m[+]\033[0m {message}")
        else:
            print(f"[+] {message}")
        self.logger.info(message)

    def print_error(self, message: str) -> None:
        """Print error message with formatting"""
        if self.config.get("colored_output", True):
            print(f"\033[91m[!]\033[0m {message}")
        else:
            print(f"[!] {message}")
        self.logger.error(message)

    def print_warning(self, message: str) -> None:
        """Print warning message with formatting"""
        if self.config.get("colored_output", True):
            print(f"\033[93m[!]\033[0m {message}")
        else:
            print(f"[!] {message}")
        self.logger.warning(message)

    def print_info(self, message: str) -> None:
        """Print info message with formatting"""
        if self.config.get("colored_output", True):
            print(f"\033[96m[i]\033[0m {message}")
        else:
            print(f"[i] {message}")
        self.logger.info(message)

    def print_header(self, message: str) -> None:
        """Print section header with formatting"""
        if self.config.get("colored_output", True):
            print(f"\n\033[93m{'='*50}\033[0m")
            print(f"\033[93m{message.center(50)}\033[0m")
            print(f"\033[93m{'='*50}\033[0m")
        else:
            print(f"\n{'='*50}")
            print(f"{message.center(50)}")
            print(f"{'='*50}")

    def get_user_input(
        self, prompt: str, input_type: str = "general", required: bool = True
    ) -> Optional[str]:
        """
        Get validated user input with enhanced security

        Args:
            prompt: Input prompt to display
            input_type: Type of input for validation
            required: Whether input is required

        Returns:
            Validated input string or None
        """
        while True:
            try:
                if self.config.get("colored_output", True):
                    user_input = input(f"\033[93m{prompt}\033[0m").strip()
                else:
                    user_input = input(f"{prompt}").strip()

                if not user_input and not required:
                    return None

                if not user_input and required:
                    self.print_error("Input is required. Please try again.")
                    continue

                if (
                    user_input is not None
                    and user_input != ""
                    and self.validate_input(user_input, input_type)
                ):
                    return user_input

            except KeyboardInterrupt:
                raise
            except EOFError:
                return None

    def get_user_choice(
        self, options: List[str], prompt: str = "Select an option: "
    ) -> Optional[int]:
        """
        Get user choice from a list of options

        Args:
            options: List of option strings
            prompt: Prompt to display

        Returns:
            Selected option index (0-based) or None
        """
        print("\nAvailable options:")
        for i, option in enumerate(options, 1):
            print(f"{i}. {option}")

        while True:
            try:
                choice = self.get_user_input(prompt, required=False)
                if choice is None:
                    return None

                if choice.lower() in ["q", "quit", "exit"]:
                    return None

                choice_num = int(choice)
                if 1 <= choice_num <= len(options):
                    return choice_num - 1
                else:
                    self.print_error(
                        f"Please select a number between 1 and {len(options)}"
                    )

            except ValueError:
                self.print_error("Please enter a valid number")
            except KeyboardInterrupt:
                return None

    def save_results(
        self, results: Dict[str, Any], filename: Optional[str] = None
    ) -> bool:
        """
        Save scan results to file

        Args:
            results: Results dictionary to save
            filename: Optional custom filename

        Returns:
            True if successful, False otherwise
        """
        import os

        try:
            output_dir = self.config.get("output_dir", "./reports/output")
            os.makedirs(output_dir, exist_ok=True)

            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{self.module_name}_{timestamp}.json"

            filepath = os.path.join(output_dir, filename)

            with open(filepath, "w") as f:
                json.dump(results, f, indent=2, default=str)

            self.print_success(f"Results saved to: {filepath}")
            return True

        except Exception as e:
            self.print_error(f"Failed to save results: {e}")
            return False

    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a result to the module's results list"""
        result["timestamp"] = time.time()
        result["module"] = self.module_name
        self.results.append(result)

        # Auto-save if enabled
        if self.config.get("auto_save_results", True):
            self.save_results({"results": self.results})

    def clear_results(self) -> None:
        """Clear stored results"""
        self.results.clear()
        self.print_info("Results cleared")

    def show_progress(self, current: int, total: int, prefix: str = "Progress") -> None:
        """
        Display progress bar

        Args:
            current: Current progress value
            total: Total progress value
            prefix: Prefix text for progress bar
        """
        if total == 0:
            return

        percent = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)

        bar = "█" * filled_length + "-" * (bar_length - filled_length)

        if self.config.get("colored_output", True):
            print(
                f"\r\033[96m{prefix}\033[0m |{bar}| {current}/{total} ({percent:.1f}%)",
                end="",
                flush=True,
            )
        else:
            print(
                f"\r{prefix} |{bar}| {current}/{total} ({percent:.1f}%)",
                end="",
                flush=True,
            )

        if current == total:
            print()  # New line when complete
