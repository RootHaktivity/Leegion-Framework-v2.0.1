"""
Configuration management for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any
from core.security import SecurityManager

# Default configuration
DEFAULT_CONFIG = {
    "log_level": "INFO",
    "vpn_config_dir": "./vpn_configs",
    "output_dir": "./reports/output",
    "nmap_default_args": "-sC -sV",
    "wpscan_api_token": "",
    "subdomain_wordlist": "./wordlists/subdomains.txt",
    "directory_wordlist": "./wordlists/dirb/common.txt",
    "max_threads": 50,
    "timeout": 30,
    "user_agent": "Leegion-Framework/2.0",
    "report_formats": ["json", "xml", "csv"],
    "auto_save_results": True,
    "colored_output": True,
    "session_timeout": 3600,
}

security_manager = SecurityManager()


def load_config(config_path: str = "config/config.json") -> Dict[str, Any]:
    """
    Load configuration from JSON file, create default if not exists

    Args:
        config_path: Path to configuration file

    Returns:
        Dictionary containing configuration
    """
    config_file = Path(config_path)

    # Create config directory if it doesn't exist
    config_file.parent.mkdir(parents=True, exist_ok=True)

    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                config = json.load(f)

            # Decrypt API token if present and looks encrypted
            token = config.get("wpscan_api_token", "")
            if token and token.startswith("enc:"):
                try:
                    config["wpscan_api_token"] = (
                        security_manager.decrypt_sensitive_data(token[4:])
                    )
                except Exception:
                    config["wpscan_api_token"] = ""

            # Merge with defaults to ensure all keys exist
            merged_config = DEFAULT_CONFIG.copy()
            merged_config.update(config)

            # Save merged config back to file
            if merged_config != config:
                save_config(merged_config, config_path)

            return merged_config

        except (json.JSONDecodeError, IOError) as e:
            print(f"\033[91m[!]\033[0m Error loading config file: {e}")
            print(f"\033[93m[!]\033[0m Using default configuration")
            save_config(DEFAULT_CONFIG, config_path)
            return DEFAULT_CONFIG.copy()
    else:
        # Create default config file
        save_config(DEFAULT_CONFIG, config_path)
        print(f"\033[92m[+]\033[0m Created default configuration at {config_path}")
        return DEFAULT_CONFIG.copy()


def save_config(
    config: Dict[str, Any], config_path: str = "config/config.json"
) -> bool:
    """
    Save configuration to JSON file

    Args:
        config: Configuration dictionary to save
        config_path: Path to save configuration file

    Returns:
        True if successful, False otherwise
    """
    try:
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)

        # Encrypt API token if present and not already encrypted
        token = config.get("wpscan_api_token", "")
        if token and not token.startswith("enc:"):
            try:
                encrypted = security_manager.encrypt_sensitive_data(token)
                config["wpscan_api_token"] = "enc:" + encrypted
            except Exception:
                pass

        with open(config_file, "w") as f:
            json.dump(config, f, indent=4, sort_keys=True)

        return True

    except (IOError, TypeError) as e:
        print(f"\033[91m[!]\033[0m Error saving config file: {e}")
        return False


def get_config_value(
    key: str, default: Any = None, config_path: str = "config/config.json"
) -> Any:
    """
    Get a specific configuration value

    Args:
        key: Configuration key to retrieve
        default: Default value if key not found
        config_path: Path to configuration file

    Returns:
        Configuration value or default
    """
    config = load_config(config_path)
    return config.get(key, default)


def update_config_value(
    key: str, value: Any, config_path: str = "config/config.json"
) -> bool:
    """
    Update a specific configuration value

    Args:
        key: Configuration key to update
        value: New value
        config_path: Path to configuration file

    Returns:
        True if successful, False otherwise
    """
    config = load_config(config_path)
    config[key] = value
    return save_config(config, config_path)


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration values

    Args:
        config: Configuration dictionary to validate

    Returns:
        True if valid, False otherwise
    """
    required_keys = [
        "log_level",
        "vpn_config_dir",
        "output_dir",
        "max_threads",
        "timeout",
    ]

    # Check required keys exist
    for key in required_keys:
        if key not in config:
            print(f"\033[91m[!]\033[0m Missing required config key: {key}")
            return False

    # Validate log level
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if config["log_level"] not in valid_log_levels:
        print(f"\033[91m[!]\033[0m Invalid log level: {config['log_level']}")
        return False

    # Validate numeric values
    if not isinstance(config["max_threads"], int) or config["max_threads"] <= 0:
        print(f"\033[91m[!]\033[0m Invalid max_threads value: {config['max_threads']}")
        return False

    if not isinstance(config["timeout"], (int, float)) or config["timeout"] <= 0:
        print(f"\033[91m[!]\033[0m Invalid timeout value: {config['timeout']}")
        return False

    return True


def create_directories_from_config(config: Dict[str, Any]) -> None:
    """
    Create necessary directories based on configuration

    Args:
        config: Configuration dictionary
    """
    directories = [
        config.get("vpn_config_dir", "./vpn_configs"),
        config.get("output_dir", "./reports/output"),
        "./logs",
    ]

    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            print(f"\033[91m[!]\033[0m Failed to create directory {directory}: {e}")


def get_wordlist_path(config_key: str, config: Dict[str, Any]) -> str:
    """
    Get wordlist path with fallbacks if file doesn't exist

    Args:
        config_key: Configuration key for wordlist
        config: Configuration dictionary

    Returns:
        Path to wordlist file
    """
    wordlist_path = config.get(config_key, "")

    # Check if the configured path exists
    if os.path.exists(wordlist_path):
        return wordlist_path

    # Fallback paths to check
    fallback_paths = {
        "subdomain_wordlist": [
            "./wordlists/subdomains.txt",
            "/usr/share/wordlists/subdomains.txt",
            "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "directory_wordlist": [
            "./wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
        ],
    }

    if config_key in fallback_paths:
        for fallback_path in fallback_paths[config_key]:
            if os.path.exists(fallback_path):
                return fallback_path

    # If no wordlist found, return the original path (will be handled by modules)
    return wordlist_path
