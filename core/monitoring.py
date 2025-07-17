"""
System monitoring and performance tracking for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import psutil
import threading
import time
from datetime import datetime
import json
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List, Any, Optional, Callable

from core.logger import setup_logger

# Try to import psutil, provide fallback if not available
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

    # Mock psutil for basic functionality
    class MockPsutil:
        @staticmethod
        def cpu_percent(interval=1):
            return 0.0

        @staticmethod
        def virtual_memory():
            class MockMemory:
                percent = 0.0

            return MockMemory()

        @staticmethod
        def disk_usage(path):
            class MockDisk:
                used = 0
                total = 1

            return MockDisk()

        class Process:
            def memory_info(self):
                class MockMemoryInfo:
                    rss = 0

                return MockMemoryInfo()

    psutil = MockPsutil()


class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthMetric:
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    active_threads: int
    network_requests_per_sec: float
    error_count: int
    warning_count: int


@dataclass
class Alert:
    timestamp: float
    level: AlertLevel
    message: str
    source: str
    details: Dict[str, Any]


class MonitoringSystem:
    """Comprehensive monitoring system for Leegion Framework"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics_history: List[HealthMetric] = []
        self.alerts: List[Alert] = []
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        self.monitoring_active = False
        self.monitor_thread = None

        # Thresholds
        self.cpu_threshold = config.get("monitoring_cpu_threshold", 80.0)
        self.memory_threshold = config.get("monitoring_memory_threshold", 85.0)
        self.disk_threshold = config.get("monitoring_disk_threshold", 90.0)
        self.error_threshold = config.get("monitoring_error_threshold", 10)

        # Monitoring interval
        self.monitor_interval = config.get("monitoring_interval", 30)  # seconds

        # Metrics retention
        self.max_metrics_history = config.get("max_metrics_history", 1000)

        # Network request tracking
        self.network_requests = 0
        self.last_network_reset = time.time()
        self.network_lock = threading.Lock()

    def start_monitoring(self):
        """Start the monitoring system"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._collect_metrics()
                self._check_thresholds()
                time.sleep(self.monitor_interval)
            except Exception:
                self._create_alert(
                    AlertLevel.ERROR, f"Monitoring error", "monitoring_system"
                )

    def _collect_metrics(self):
        """Collect system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # Disk usage
            disk = psutil.disk_usage("/")
            disk_usage_percent = (disk.used / disk.total) * 100

            # Active threads
            active_threads = threading.active_count()

            # Network requests per second
            with self.network_lock:
                current_time = time.time()
                time_diff = current_time - self.last_network_reset
                if time_diff >= 1.0:  # Reset every second
                    network_requests_per_sec = self.network_requests / time_diff
                    self.network_requests = 0
                    self.last_network_reset = current_time
                else:
                    network_requests_per_sec = 0

            # Error and warning counts
            error_count = len(
                [
                    a
                    for a in self.alerts[-100:]
                    if a.level in [AlertLevel.ERROR, AlertLevel.CRITICAL]
                ]
            )
            warning_count = len(
                [a for a in self.alerts[-100:] if a.level == AlertLevel.WARNING]
            )

            # Create metric
            metric = HealthMetric(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage_percent=disk_usage_percent,
                active_threads=active_threads,
                network_requests_per_sec=network_requests_per_sec,
                error_count=error_count,
                warning_count=warning_count,
            )

            # Add to history
            self.metrics_history.append(metric)

            # Trim history if too long
            if len(self.metrics_history) > self.max_metrics_history:
                self.metrics_history = self.metrics_history[-self.max_metrics_history :]

        except Exception as e:
            self._create_alert(
                AlertLevel.ERROR, f"Metrics collection error: {e}", "monitoring_system"
            )

    def _check_thresholds(self):
        """Check metrics against thresholds and create alerts"""
        if not self.metrics_history:
            return

        latest = self.metrics_history[-1]

        # CPU threshold check
        if latest.cpu_percent > self.cpu_threshold:
            self._create_alert(
                AlertLevel.WARNING,
                f"High CPU usage: {latest.cpu_percent:.1f}%",
                "system_metrics",
                {"cpu_percent": latest.cpu_percent, "threshold": self.cpu_threshold},
            )

        # Memory threshold check
        if latest.memory_percent > self.memory_threshold:
            self._create_alert(
                AlertLevel.WARNING,
                f"High memory usage: {latest.memory_percent:.1f}%",
                "system_metrics",
                {
                    "memory_percent": latest.memory_percent,
                    "threshold": self.memory_threshold,
                },
            )

        # Disk threshold check
        if latest.disk_usage_percent > self.disk_threshold:
            self._create_alert(
                AlertLevel.WARNING,
                f"High disk usage: {latest.disk_usage_percent:.1f}%",
                "system_metrics",
                {
                    "disk_usage_percent": latest.disk_usage_percent,
                    "threshold": self.disk_threshold,
                },
            )

        # Error threshold check
        if latest.error_count > self.error_threshold:
            self._create_alert(
                AlertLevel.ERROR,
                f"High error count: {latest.error_count}",
                "system_metrics",
                {"error_count": latest.error_count, "threshold": self.error_threshold},
            )

    def _create_alert(
        self,
        level: AlertLevel,
        message: str,
        source: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Create and dispatch an alert"""
        alert = Alert(
            timestamp=time.time(),
            level=level,
            message=message,
            source=source,
            details=details or {},
        )

        self.alerts.append(alert)

        # Trim alerts if too many
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]

        # Dispatch to callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                # Don't let callback errors break monitoring
                pass

    def track_network_request(self):
        """Track a network request for rate limiting monitoring"""
        with self.network_lock:
            self.network_requests += 1

    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add a callback function for alerts"""
        self.alert_callbacks.append(callback)

    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        if not self.metrics_history:
            return {"status": "no_data", "message": "No metrics collected yet"}

        latest = self.metrics_history[-1]

        # Determine overall health
        if (
            latest.cpu_percent > self.cpu_threshold
            or latest.memory_percent > self.memory_threshold
        ):
            status = "warning"
        elif latest.error_count > self.error_threshold:
            status = "error"
        else:
            status = "healthy"

        return {
            "status": status,
            "timestamp": latest.timestamp,
            "metrics": asdict(latest),
            "thresholds": {
                "cpu": self.cpu_threshold,
                "memory": self.memory_threshold,
                "disk": self.disk_threshold,
                "errors": self.error_threshold,
            },
        }

    def get_metrics_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get metrics history for the specified time period"""
        cutoff_time = time.time() - (hours * 3600)
        recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]
        return [asdict(m) for m in recent_metrics]

    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent alerts for the specified time period"""
        cutoff_time = time.time() - (hours * 3600)
        recent_alerts = [a for a in self.alerts if a.timestamp >= cutoff_time]
        return [asdict(a) for a in recent_alerts]

    def export_metrics(self, filepath: str):
        """Export metrics to JSON file"""
        try:
            data = {
                "export_timestamp": time.time(),
                "metrics": [asdict(m) for m in self.metrics_history],
                "alerts": [asdict(a) for a in self.alerts],
            }

            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)

        except Exception as e:
            self._create_alert(
                AlertLevel.ERROR, f"Metrics export failed: {e}", "monitoring_system"
            )


# Global monitoring instance
monitoring_system: Optional[MonitoringSystem] = None


def initialize_monitoring(config: Dict[str, Any]):
    """Initialize the global monitoring system"""
    global monitoring_system
    monitoring_system = MonitoringSystem(config)
    monitoring_system.start_monitoring()


def get_monitoring_system() -> Optional[MonitoringSystem]:
    """Get the global monitoring system instance"""
    return monitoring_system


def track_network_request():
    """Track a network request (convenience function)"""
    if monitoring_system:
        monitoring_system.track_network_request()


def create_alert(
    level: AlertLevel,
    message: str,
    source: str,
    details: Optional[Dict[str, Any]] = None,
):
    """Create an alert (convenience function)"""
    if monitoring_system:
        monitoring_system._create_alert(level, message, source, details or {})
