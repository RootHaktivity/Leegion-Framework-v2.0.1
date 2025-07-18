"""
Security module for Leegion Framework.

This module provides comprehensive security validation, input sanitization,
and security utilities for the framework.
"""

import base64
import hashlib
import os
import re
import secrets
import time
import threading
from pathlib import Path
from typing import Dict, Any, List

from cryptography.fernet import Fernet


class SecurityManager:
    """Centralized security management for the framework"""

    def __init__(self, config_dir: str = "~/.config/leegion"):
        self.config_dir = Path(config_dir).expanduser()
        self.key_file = self.config_dir / ".security_key"
        self._ensure_key_exists()

    def _ensure_key_exists(self):
        """Ensure encryption key exists"""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        if not self.key_file.exists():
            # Generate new key
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(self.key_file, 0o600)

    def _get_fernet(self) -> Fernet:
        """Get Fernet instance for encryption/decryption"""
        with open(self.key_file, "rb") as f:
            key = f.read()
        return Fernet(key)

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive configuration data"""
        fernet = self._get_fernet()
        encrypted = fernet.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive configuration data"""
        fernet = self._get_fernet()
        encrypted = base64.b64decode(encrypted_data.encode())
        decrypted = fernet.decrypt(encrypted)
        return decrypted.decode()

    def secure_file_path(self, file_path: str) -> bool:
        """
        Validate file path for security (prevent path traversal and symlink attacks)
        """
        try:
            resolved_path = Path(file_path).expanduser().resolve()
            resolved_path_str = str(resolved_path)

            # Block access to system directories even if within allowed directories
            system_dirs = [
                "/etc",
                "/var",
                "/usr",
                "/bin",
                "/sbin",
                "/proc",
                "/sys",
                "/boot",
                "/dev",
            ]
            for sys_dir in system_dirs:
                if sys_dir in resolved_path_str:
                    return False

            for allowed_dir in [
                Path.cwd().resolve(),
                Path.home().resolve(),
                self.config_dir.resolve(),
            ]:
                allowed_dir_str = str(allowed_dir)

                if (
                    resolved_path_str != allowed_dir_str
                    and resolved_path_str.startswith(allowed_dir_str + "/")
                ):
                    # Check all parents are not symlinks
                    for parent in resolved_path.parents:
                        if str(parent) == allowed_dir_str:
                            break
                        if parent.is_symlink():
                            return False
                    if not resolved_path.is_symlink():
                        return True
            return False
        except (ValueError, RuntimeError):
            return False

    def sanitize_command(self, command: List[str]) -> List[str]:
        """Sanitize command arguments for subprocess execution"""
        sanitized = []
        dangerous_substrings = [
            "rm -rf",
            "rm -r",
            "rm -f",
            "shutdown",
            "reboot",
            "mkfs",
            "dd if=",
            ">:",
        ]

        for arg in command:
            # Remove dangerous substrings
            for ds in dangerous_substrings:
                arg = arg.replace(ds, "")
            # Remove potentially dangerous characters
            sanitized_arg = re.sub(r"[;&|`$(){}]", "", arg)
            # Limit length
            if len(sanitized_arg) > 1000:
                sanitized_arg = sanitized_arg[:1000]
            sanitized.append(sanitized_arg)

        return sanitized

    def validate_api_token(self, token: str) -> bool:
        """Validate API token format"""
        if not token:
            return False

        # Basic validation - adjust based on specific API requirements
        if len(token) < 10 or len(token) > 100:
            return False

        # Check for common patterns
        if re.match(r"^[a-zA-Z0-9_-]+$", token):
            return True

        return False

    def generate_secure_filename(self, original_name: str) -> str:
        """Generate a secure filename"""
        # Remove dangerous characters
        safe_name = re.sub(r'[<>:"/\\|?*]', "_", original_name)

        # Add random suffix for uniqueness
        random_suffix = secrets.token_hex(8)
        name, ext = os.path.splitext(safe_name)

        return f"{name}_{random_suffix}{ext}"

    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data for storage"""
        return hashlib.sha256(data.encode()).hexdigest()

    def rate_limit_check(
        self, operation: str, max_attempts: int = 10, window_seconds: int = 60
    ) -> bool:
        """Simple rate limiting check"""
        # This is a basic implementation
        # In production, consider using Redis or similar for distributed rate limiting
        rate_limit_file = self.config_dir / f".rate_limit_{operation}"

        try:
            current_time = os.path.getmtime(rate_limit_file)
            if os.path.exists(rate_limit_file):
                with open(rate_limit_file, "r") as f:
                    attempts = int(f.read().strip())

                # Check if window has passed
                if os.path.getmtime(rate_limit_file) < (current_time - window_seconds):
                    attempts = 0

                if attempts >= max_attempts:
                    return False

                attempts += 1
            else:
                attempts = 1

            # Update rate limit file
            with open(rate_limit_file, "w") as f:
                f.write(str(attempts))

            return True

        except Exception:
            # If rate limiting fails, allow the operation
            return True


def validate_input_security(
    input_value: str, input_type: str = "general"
) -> Dict[str, Any]:
    """
    Comprehensive input validation with security checks

    Returns:
        Dict with 'valid' boolean and 'reason' string
    """
    result = {"valid": True, "reason": "Valid input"}

    if not input_value or not input_value.strip():
        result = {"valid": False, "reason": "Input cannot be empty"}
        return result

    input_value = input_value.strip()

    # Check for potential injection patterns
    dangerous_patterns = [
        r"[;&|`$(){}]",  # Command injection
        r"\.{2}/",  # Path traversal
        r"<script",  # XSS
        r"javascript:",  # XSS
        r"data:",  # Data URI injection
    ]
    # Add SQL injection patterns for string/command
    if input_type in ["string", "command"]:
        dangerous_patterns += [
            r"(\'|\").*\b(OR|AND)\b.*(\'|\")",  # ' OR '1'='1'
            r";",  # Any semicolon
            r"--",  # Any double dash
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|"
            r"REPLACE|TRUNCATE)\b",
            # ; followed by SQL keyword
            r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|"
            r"REPLACE|TRUNCATE)\b",
        ]

    for pattern in dangerous_patterns:
        if re.search(pattern, input_value, re.IGNORECASE):
            result = {
                "valid": False,
                "reason": (f"Potentially dangerous pattern detected: {pattern}"),
            }
            return result

    # Type-specific validation
    if input_type == "ip":
        ip_pattern = (
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        if not re.match(ip_pattern, input_value):
            result = {"valid": False, "reason": "Invalid IP address format"}

    elif input_type == "url":
        url_pattern = (
            r"^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*)?"
            r"(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?$"
        )
        if not re.match(url_pattern, input_value):
            result = {"valid": False, "reason": "Invalid URL format"}

    elif input_type == "domain":
        domain_pattern = (
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )
        if not re.match(domain_pattern, input_value):
            result = {"valid": False, "reason": "Invalid domain format"}

    elif input_type == "file_path":
        # Block access to system files and directories
        dangerous_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/",
            "/sys/",
            "/dev/",
            "/boot/",
        ]
        for dangerous_path in dangerous_paths:
            if dangerous_path in input_value:
                result = {
                    "valid": False,
                    "reason": (
                        f"Access to system file/directory blocked: " f"{dangerous_path}"
                    ),
                }
                return result

    elif input_type == "command":
        # Block dangerous commands
        dangerous_commands = [
            "rm -rf",
            "rm -r",
            "rm -f",
            "shutdown",
            "reboot",
            "mkfs",
            "dd if=",
            ">:",
        ]
        for dangerous_cmd in dangerous_commands:
            if dangerous_cmd in input_value:
                result = {
                    "valid": False,
                    "reason": (f"Dangerous command blocked: {dangerous_cmd}"),
                }
                return result

    # Length limits
    if len(input_value) > 1000:
        result = {"valid": False, "reason": "Input too long (max 1000 characters)"}

    return result


class InMemoryRateLimiter:
    """Thread-safe in-memory rate limiter for per-process network operations"""

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.lock = threading.Lock()
        self.calls = []  # List of timestamps

    def allow(self) -> bool:
        now = time.time()
        with self.lock:
            # Remove calls outside the window
            self.calls = [t for t in self.calls if now - t < self.period]
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            return False


# Singleton instance for modules to use
network_rate_limiter = InMemoryRateLimiter(
    max_calls=10, period=1.0
)  # 10 calls per second

# Global security manager instance
security_manager = SecurityManager()
