"""
Integration tests for Leegion Framework v2.0

Tests end-to-end functionality, error handling, and performance
"""

import pytest
import tempfile
import os
import time
import threading
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import modules to test
from modules.vpn_manager import VPNManager
from modules.nmap_scanner import NmapScanner
from modules.wpscan_integration import WPScanIntegration
from modules.subdomain_enum import SubdomainEnumerator
from modules.directory_bruteforce import DirectoryBruteforcer
from modules.ssl_analyzer import SSLAnalyzer
from modules.command_helper import CommandHelper
from modules.file_downloader import FileDownloader
from modules.reverse_shell_generator import ReverseShellGenerator

# Test configuration
TEST_CONFIG = {
    "log_level": "DEBUG",
    "vpn_config_dir": "./test_vpn_configs",
    "output_dir": "./test_reports",
    "max_threads": 5,
    "timeout": 10,
    "colored_output": False,
}


class TestModuleIntegration:
    """Integration tests for all modules"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = TEST_CONFIG.copy()
        self.test_config["output_dir"] = self.temp_dir

        # Create test directories
        os.makedirs(self.test_config["vpn_config_dir"], exist_ok=True)
        os.makedirs(self.test_config["output_dir"], exist_ok=True)

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil

        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_vpn_manager_initialization(self):
        """Test VPN manager initialization and basic functionality"""
        vpn = VPNManager(self.test_config)
        assert vpn.config == self.test_config
        assert vpn.module_name == "VPN_Manager"
        assert vpn.vpn_process is None
        assert vpn.connection_stats["total_connections"] == 0

    def test_nmap_scanner_initialization(self):
        """Test Nmap scanner initialization"""
        scanner = NmapScanner(self.test_config)
        assert scanner.config == self.test_config
        assert scanner.module_name == "Nmap_Scanner"

    def test_wpscan_integration_initialization(self):
        """Test WPScan integration initialization"""
        wpscan = WPScanIntegration(self.test_config)
        assert wpscan.config == self.test_config
        assert wpscan.module_name == "WPScan_Integration"
        assert wpscan.api_token == ""

    def test_subdomain_enumerator_initialization(self):
        """Test subdomain enumerator initialization"""
        enum = SubdomainEnumerator(self.test_config)
        assert enum.config == self.test_config
        assert enum.module_name == "Subdomain_Enumerator"
        assert len(enum.discovered_subdomains) == 0

    def test_directory_bruteforcer_initialization(self):
        """Test directory bruteforcer initialization"""
        bruteforce = DirectoryBruteforcer(self.test_config)
        assert bruteforce.config == self.test_config
        assert bruteforce.module_name == "Directory_Bruteforcer"
        assert bruteforce.max_threads == 5  # From test config

    def test_ssl_analyzer_initialization(self):
        """Test SSL analyzer initialization"""
        ssl = SSLAnalyzer(self.test_config)
        assert ssl.config == self.test_config
        assert ssl.module_name == "SSL_Analyzer"
        assert ssl.timeout == 10

    def test_command_helper_initialization(self):
        """Test command helper initialization"""
        helper = CommandHelper(self.test_config)
        assert helper.config == self.test_config
        assert helper.module_name == "Command_Helper"
        assert len(helper.custom_commands) == 0

    def test_file_downloader_initialization(self):
        """Test file downloader initialization"""
        downloader = FileDownloader(self.test_config)
        assert downloader.config == self.test_config
        assert downloader.module_name == "File Downloader"
        assert os.path.exists(downloader.download_dir)

    def test_reverse_shell_generator_initialization(self):
        """Test reverse shell generator initialization"""
        generator = ReverseShellGenerator(self.test_config)
        assert generator.config == self.test_config
        assert generator.module_name == "Reverse_Shell_Generator"
        assert len(generator.payloads) > 0


class TestErrorHandling:
    """Test error handling across modules"""

    def setup_method(self):
        """Setup test environment"""
        self.test_config = TEST_CONFIG.copy()

    def test_invalid_input_handling(self):
        """Test handling of invalid user inputs"""
        vpn = VPNManager(self.test_config)

        # Test with invalid input types
        assert not vpn.validate_input("", "ip")
        assert not vpn.validate_input("invalid-ip", "ip")
        assert not vpn.validate_input("not-a-url", "url")
        assert not vpn.validate_input("invalid..domain", "domain")

    def test_network_error_handling(self):
        """Test handling of network errors"""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Network error")

            ssl = SSLAnalyzer(self.test_config)
            result = ssl._check_security_headers("example.com", 443)
            assert "error" in result

    def test_file_error_handling(self):
        """Test handling of file system errors"""
        bruteforce = DirectoryBruteforcer(self.test_config)

        # Test with non-existent file
        result = bruteforce._load_wordlist_file("/non/existent/file")
        assert result == []

    def test_subprocess_error_handling(self):
        """Test handling of subprocess errors"""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("Command not found")

            scanner = NmapScanner(self.test_config)
            # Should handle missing nmap gracefully
            scanner._execute_nmap_scan("127.0.0.1", "-p 80", "Test Scan")


class TestPerformance:
    """Test performance under load"""

    def setup_method(self):
        """Setup test environment"""
        self.test_config = TEST_CONFIG.copy()
        self.test_config["max_threads"] = 3  # Lower for testing

    def test_concurrent_operations(self):
        """Test concurrent operations across modules"""
        results = []

        def run_module(module_class, name):
            try:
                module = module_class(self.test_config)
                results.append(f"{name}: OK")
            except Exception as e:
                results.append(f"{name}: ERROR - {e}")

        # Start multiple modules concurrently
        threads = []
        modules = [
            (VPNManager, "VPN"),
            (NmapScanner, "Nmap"),
            (WPScanIntegration, "WPScan"),
            (SubdomainEnumerator, "Subdomain"),
            (DirectoryBruteforcer, "Directory"),
        ]

        for module_class, name in modules:
            thread = threading.Thread(target=run_module, args=(module_class, name))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=5)

        # Check results
        assert len(results) == len(modules)
        for result in results:
            assert "OK" in result or "ERROR" in result

    def test_memory_usage(self):
        """Test memory usage during operations"""
        try:
            import psutil
        except ImportError:
            pytest.skip("psutil not available - skipping memory test")

        import gc

        process = psutil.Process()
        initial_memory = process.memory_info().rss

        # Create multiple module instances
        modules = []
        for _ in range(10):
            modules.append(VPNManager(self.test_config))
            modules.append(NmapScanner(self.test_config))
            modules.append(SSLAnalyzer(self.test_config))

        # Force garbage collection
        gc.collect()

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (less than 50MB)
        assert memory_increase < 50 * 1024 * 1024

        # Cleanup
        del modules
        gc.collect()

    def test_rate_limiting_performance(self):
        """Test rate limiting performance"""
        from core.security import network_rate_limiter

        start_time = time.time()
        allowed_count = 0

        # Try to make 20 requests quickly
        for _ in range(20):
            if network_rate_limiter.allow():
                allowed_count += 1

        duration = time.time() - start_time

        # Should allow approximately 10 requests per second
        assert allowed_count <= 12  # Allow some variance
        assert duration < 2.0  # Should complete quickly


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def setup_method(self):
        """Setup test environment"""
        self.test_config = TEST_CONFIG.copy()

    def test_empty_config(self):
        """Test behavior with empty configuration"""
        empty_config = {}

        # Should handle gracefully
        vpn = VPNManager(empty_config)
        assert vpn.config == empty_config

    def test_very_large_inputs(self):
        """Test handling of very large inputs"""
        vpn = VPNManager(self.test_config)

        # Very long input
        long_input = "a" * 10000
        assert not vpn.validate_input(long_input, "ip")

        # Very long URL
        long_url = "http://" + "a" * 1000 + ".com"
        assert not vpn.validate_input(long_url, "url")

    def test_special_characters(self):
        """Test handling of special characters in inputs"""
        vpn = VPNManager(self.test_config)

        # Test various special characters
        special_inputs = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "127.0.0.1; rm -rf /",
            "javascript:alert('xss')",
        ]

        for input_val in special_inputs:
            assert not vpn.validate_input(input_val, "general")

    def test_boundary_values(self):
        """Test boundary values for numeric inputs"""
        vpn = VPNManager(self.test_config)

        # Port boundaries
        assert not vpn.validate_input("0", "port")  # Port 0 is invalid
        assert vpn.validate_input("1", "port")  # Port 1 is valid
        assert vpn.validate_input("65535", "port")  # Port 65535 is valid
        assert not vpn.validate_input("65536", "port")  # Port 65536 is invalid


class TestSecurityFeatures:
    """Test security features integration"""

    def setup_method(self):
        """Setup test environment"""
        self.test_config = TEST_CONFIG.copy()

    def test_encryption_decryption(self):
        """Test API token encryption/decryption"""
        from core.security import SecurityManager

        security = SecurityManager()
        test_token = "test_api_token_12345"

        # Encrypt
        encrypted = security.encrypt_sensitive_data(test_token)
        assert encrypted != test_token
        assert len(encrypted) > len(test_token)
        assert encrypted != ""

        # Decrypt
        decrypted = security.decrypt_sensitive_data(encrypted)
        assert decrypted == test_token

    def test_rate_limiting_integration(self):
        """Test rate limiting integration in modules"""
        from core.security import network_rate_limiter

        # Reset rate limiter
        network_rate_limiter.calls.clear()

        # Test that rate limiting is working
        allowed_count = 0
        for _ in range(15):
            if network_rate_limiter.allow():
                allowed_count += 1

        # Should allow approximately 10 requests
        assert allowed_count <= 12
        assert allowed_count >= 8

    def test_input_validation_integration(self):
        """Test input validation integration"""
        from core.security import validate_input_security

        # Test various input types
        test_cases = [
            ("127.0.0.1", "ip", True),
            ("invalid-ip", "ip", False),
            ("https://example.com", "url", True),
            ("not-a-url", "url", False),
            ("example.com", "domain", True),
            ("invalid..domain", "domain", False),
        ]

        for input_val, input_type, expected in test_cases:
            result = validate_input_security(input_val, input_type)
            assert result["valid"] == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
