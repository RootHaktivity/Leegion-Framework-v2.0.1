"""
Enhanced logging system for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for terminal output"""

    # Color codes
    COLORS = {
        "DEBUG": "\033[94m",  # Blue
        "INFO": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",  # Red
        "CRITICAL": "\033[95m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record):
        # Add color to levelname
        if record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}"
                f"{record.levelname}"
                f"{self.COLORS['RESET']}"
            )

        return super().format(record)


class LeegionLogger:
    """Enhanced logger class for Leegion Framework"""

    def __init__(self, name: str = "leegion", log_level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))

        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """Setup file and console handlers"""

        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # File handler with rotation
        log_file = log_dir / f"leegion_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"  # 10MB
        )

        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_formatter)

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = ColoredFormatter(
            "%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, **kwargs)

    def log_scan_start(self, scan_type: str, target: str):
        """Log scan start"""
        self.info(f"Starting {scan_type} scan on target: {target}")

    def log_scan_complete(self, scan_type: str, target: str, duration: float):
        """Log scan completion"""
        self.info(f"Completed {scan_type} scan on {target} in {duration:.2f} seconds")

    def log_error_with_context(self, error: Exception, context: str):
        """Log error with additional context"""
        self.error(f"Error in {context}: {type(error).__name__}: {error}")

    def log_vpn_connection(self, config_name: str, status: str):
        """Log VPN connection events"""
        self.info(f"VPN {status}: {config_name}")

    def log_module_execution(self, module_name: str, action: str):
        """Log module execution"""
        self.info(f"Module {module_name}: {action}")


def setup_logger(log_level: str = "INFO") -> LeegionLogger:
    """
    Setup and return a configured logger instance

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured LeegionLogger instance
    """
    return LeegionLogger("leegion", log_level)


# Module-level logger for convenience
logger = setup_logger()


def log_function_call(func):
    """Decorator to log function calls"""

    def wrapper(*args, **kwargs):
        logger.debug(f"Calling function: {func.__name__}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Function {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Function {func.__name__} failed: {e}")
            raise

    return wrapper


def log_execution_time(func):
    """Decorator to log function execution time"""
    import time

    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        logger.debug(
            f"Function {func.__name__} executed in {execution_time:.2f} seconds"
        )
        return result

    return wrapper
