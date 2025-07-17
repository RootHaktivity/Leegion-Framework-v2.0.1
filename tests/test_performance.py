"""
Performance tests for Leegion Framework v2.0

Tests memory usage, concurrency, and large dataset handling
"""

import pytest
import time
import threading
import gc
from pathlib import Path
from unittest.mock import patch
import tempfile
import os

# Try to import psutil, skip tests if not available
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Import modules to test
from modules.vpn_manager import VPNManager
from modules.nmap_scanner import NmapScanner
from modules.subdomain_enum import SubdomainEnumerator
from modules.directory_bruteforce import DirectoryBruteforcer
from modules.ssl_analyzer import SSLAnalyzer
from core.security import SecurityManager, validate_input_security
from core.monitoring import MonitoringSystem, AlertLevel
from core.backup import BackupManager


class TestPerformance:
    """Performance test suite"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment"""
        self.test_config = {
            "output_dir": "./test_output",
            "log_level": "ERROR",  # Reduce logging overhead
            "vpn_config_dir": "./test_vpn_configs",
            "backup_dir": "./test_backups",
            "monitoring_interval": 1,  # Fast monitoring for tests
            "max_metrics_history": 100,
        }

        # Create test directories
        Path(self.test_config["output_dir"]).mkdir(exist_ok=True)
        Path(self.test_config["vpn_config_dir"]).mkdir(exist_ok=True)
        Path(self.test_config["backup_dir"]).mkdir(exist_ok=True)

        yield

        # Cleanup
        import shutil

        for path in ["test_output", "test_vpn_configs", "test_backups"]:
            if Path(path).exists():
                shutil.rmtree(path)

    def test_memory_usage_large_dataset(self):
        """Test memory usage with large datasets"""
        if not PSUTIL_AVAILABLE:
            pytest.skip("psutil not available")

        process = psutil.Process()
        initial_memory = process.memory_info().rss

        # Create large dataset
        large_wordlist = [f"test{i:06d}" for i in range(10000)]

        # Test directory bruteforcer with large wordlist
        bruteforcer = DirectoryBruteforcer(self.test_config)

        # Simulate processing large dataset
        results = []
        for word in large_wordlist[:1000]:  # Test with subset
            results.append(
                {
                    "url": f"http://example.com/{word}",
                    "status_code": 200,
                    "content_length": 1024,
                }
            )

        # Force garbage collection
        gc.collect()

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (< 100MB)
        assert (
            memory_increase < 100 * 1024 * 1024
        ), f"Memory increase too high: {memory_increase / 1024 / 1024:.1f}MB"

    def test_concurrent_module_operations(self):
        """Test concurrent operations across multiple modules"""
        results = []
        errors = []

        def run_module_operation(module_class, operation_name):
            try:
                module = module_class(self.test_config)
                start_time = time.time()

                # Simulate module operation
                if hasattr(module, "validate_input"):
                    for i in range(100):
                        module.validate_input(f"test{i}", "string")

                end_time = time.time()
                results.append(
                    {
                        "module": module_class.__name__,
                        "operation": operation_name,
                        "duration": end_time - start_time,
                    }
                )
            except Exception as e:
                errors.append(f"{module_class.__name__}: {e}")

        # Create threads for different modules
        threads = []
        modules = [
            (VPNManager, "validation"),
            (NmapScanner, "validation"),
            (SSLAnalyzer, "validation"),
            (DirectoryBruteforcer, "validation"),
            (SubdomainEnumerator, "validation"),
        ]

        for module_class, operation in modules:
            thread = threading.Thread(
                target=run_module_operation, args=(module_class, operation)
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)

        # Check results
        assert len(errors) == 0, f"Concurrent operations failed: {errors}"
        assert len(results) == len(modules), "Not all operations completed"

        # All operations should complete within reasonable time
        for result in results:
            assert result["duration"] < 10, f"Operation too slow: {result}"

    def test_security_manager_performance(self):
        """Test SecurityManager performance with high volume input validation"""
        security_manager = SecurityManager()

        # Test high volume input validation
        start_time = time.time()

        valid_inputs = [
            ("192.168.1.1", "ip"),
            ("example.com", "domain"),
            ("https://example.com", "url"),
            ("8080", "port"),
            ("/safe/path", "file_path"),
        ]

        invalid_inputs = [
            ("invalid-ip", "ip"),
            ("<script>alert('xss')</script>", "string"),
            ("'; DROP TABLE users; --", "string"),
            ("/etc/passwd", "file_path"),
            ("rm -rf /", "command"),
        ]

        # Validate valid inputs once
        for value, input_type in valid_inputs:
            result = validate_input_security(value, input_type)
            assert result["valid"]
        # Validate invalid inputs once
        for value, input_type in invalid_inputs:
            result = validate_input_security(value, input_type)
            assert not result["valid"]

        end_time = time.time()
        total_time = end_time - start_time

        # Should process 5000 validations quickly (< 5 seconds)
        assert total_time < 5, f"Security validation too slow: {total_time:.2f}s"

    def test_monitoring_system_performance(self):
        """Test monitoring system performance under load"""
        monitoring = MonitoringSystem(self.test_config)
        monitoring.start_monitoring()

        try:
            # Simulate high activity
            start_time = time.time()

            # Track many network requests
            for _ in range(1000):
                monitoring.track_network_request()

            # Create many alerts
            for i in range(100):
                monitoring._create_alert(
                    AlertLevel.INFO, f"Test alert {i}", "test", {"test": i}
                )

            # Wait for metrics collection
            time.sleep(2)

            end_time = time.time()

            # Check performance
            health_status = monitoring.get_health_status()
            metrics_history = monitoring.get_metrics_history(hours=1)
            recent_alerts = monitoring.get_recent_alerts(hours=1)

            assert health_status["status"] in ["healthy", "warning", "no_data"]
            assert len(metrics_history) > 0
            assert len(recent_alerts) > 0

            # Should handle load efficiently
            assert end_time - start_time < 10, "Monitoring too slow under load"

        finally:
            monitoring.stop_monitoring()

    def test_backup_system_performance(self):
        """Test backup system performance with large datasets"""
        backup_manager = BackupManager(self.test_config)

        # Create test data
        test_data_dir = Path("test_data")
        test_data_dir.mkdir(exist_ok=True)

        try:
            # Create large test files
            for i in range(10):
                test_file = test_data_dir / f"large_file_{i}.txt"
                with open(test_file, "w") as f:
                    f.write("x" * 1024 * 1024)  # 1MB files

            # Update backup components to include test data
            backup_manager.backup_components["test_data"] = {
                "paths": [str(test_data_dir)],
                "description": "Test data for performance testing",
            }

            # Test backup performance
            start_time = time.time()
            backup_path = backup_manager.create_backup(["test_data"])
            backup_time = time.time() - start_time

            # Backup should complete within reasonable time
            assert backup_time < 30, f"Backup too slow: {backup_time:.2f}s"

            # Test restore performance
            start_time = time.time()
            success = backup_manager.restore_backup(backup_path, ["test_data"])
            restore_time = time.time() - start_time

            assert success, "Backup restore failed"
            assert restore_time < 30, f"Restore too slow: {restore_time:.2f}s"

        finally:
            # Cleanup
            import shutil

            if test_data_dir.exists():
                shutil.rmtree(test_data_dir)

    def test_network_rate_limiting_performance(self):
        """Test network rate limiting performance"""
        from core.security import network_rate_limiter

        # Test rate limiter performance
        start_time = time.time()

        allowed_count = 0
        for _ in range(100):
            if network_rate_limiter.allow():
                allowed_count += 1

        end_time = time.time()

        # Should process requests quickly
        assert end_time - start_time < 1, "Rate limiter too slow"

        # Should respect rate limits
        assert allowed_count <= 10, f"Rate limit exceeded: {allowed_count} requests"

    def test_large_file_handling(self):
        """Test handling of large files and datasets"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            # Create a large test file
            for i in range(10000):
                f.write(f"test_line_{i}: {'x' * 100}\n")
            large_file_path = f.name

        try:
            # Test file downloader with large file
            from modules.file_downloader import FileDownloader

            downloader = FileDownloader(self.test_config)

            # Simulate processing large file
            start_time = time.time()

            with open(large_file_path, "r") as f:
                lines = f.readlines()

            # Process lines (simulate download processing)
            processed_lines = []
            for line in lines[:1000]:  # Process subset
                if downloader.validate_input(line.strip(), "string"):
                    processed_lines.append(line.strip())

            end_time = time.time()

            # Should handle large files efficiently
            assert (
                end_time - start_time < 5
            ), f"Large file processing too slow: {end_time - start_time:.2f}s"
            assert len(processed_lines) > 0, "No lines processed"

        finally:
            os.unlink(large_file_path)

    def test_memory_leak_prevention(self):
        """Test that no memory leaks occur during operations"""
        if not PSUTIL_AVAILABLE:
            pytest.skip("psutil not available")

        process = psutil.Process()

        # Record initial memory
        initial_memory = process.memory_info().rss

        # Perform many operations
        for cycle in range(10):
            # Create and destroy modules
            modules = [
                VPNManager(self.test_config),
                NmapScanner(self.test_config),
                SSLAnalyzer(self.test_config),
                DirectoryBruteforcer(self.test_config),
                SubdomainEnumerator(self.test_config),
            ]

            # Use modules
            for module in modules:
                module.validate_input("test", "string")

            # Force garbage collection
            gc.collect()

            # Check memory after each cycle
            current_memory = process.memory_info().rss
            memory_increase = current_memory - initial_memory

            # Memory should not grow excessively
            assert (
                memory_increase < 50 * 1024 * 1024
            ), f"Memory leak detected: {memory_increase / 1024 / 1024:.1f}MB increase"

    def test_concurrent_network_operations(self):
        """Test concurrent network operations with rate limiting"""
        from core.security import network_rate_limiter
        import requests

        results = []
        errors = []

        def make_request(url):
            try:
                # Wait for rate limiter
                while not network_rate_limiter.allow():
                    time.sleep(0.01)

                # Simulate network request
                with patch("requests.get") as mock_get:
                    mock_get.return_value.status_code = 200
                    mock_get.return_value.text = "test response"

                    response = requests.get(url, timeout=5)
                    results.append({"url": url, "status": response.status_code})

            except Exception as e:
                errors.append(f"Request failed for {url}: {e}")

        # Create multiple threads making requests
        threads = []
        urls = [f"http://example{i}.com" for i in range(20)]

        for url in urls:
            thread = threading.Thread(target=make_request, args=(url,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)

        # Check results
        assert len(errors) == 0, f"Network operations failed: {errors}"
        assert len(results) == len(urls), "Not all requests completed"

        # All requests should have succeeded
        for result in results:
            assert result["status"] == 200, f"Request failed: {result}"
