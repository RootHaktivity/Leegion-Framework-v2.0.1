"""
Security tests for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import unittest
import sys
from pathlib import Path
from core.security import SecurityManager, validate_input_security

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestSecurityManager(unittest.TestCase):
    """Test security manager functionality"""

    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()

    def test_encryption_decryption(self):
        """Test encryption and decryption of sensitive data"""
        test_data = "sensitive_api_token_12345"

        # Encrypt
        encrypted = self.security_manager.encrypt_sensitive_data(test_data)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, test_data)

        # Decrypt
        decrypted = self.security_manager.decrypt_sensitive_data(encrypted)
        self.assertEqual(decrypted, test_data)

    def test_secure_file_path(self):
        """Test file path security validation"""
        # Valid paths
        self.assertTrue(self.security_manager.secure_file_path("./config/config.json"))
        self.assertTrue(self.security_manager.secure_file_path("~/config/test.json"))

        # Invalid paths (path traversal attempts)
        self.assertFalse(self.security_manager.secure_file_path("../../../etc/passwd"))
        self.assertFalse(self.security_manager.secure_file_path("/etc/shadow"))

    def test_sanitize_command(self):
        """Test command sanitization"""
        dangerous_command = ["nmap", "-sS", "192.168.1.1; rm -rf /"]
        sanitized = self.security_manager.sanitize_command(dangerous_command)

        # Should remove dangerous characters
        self.assertNotIn(";", " ".join(sanitized))
        self.assertNotIn("rm -rf", " ".join(sanitized))

    def test_validate_api_token(self):
        """Test API token validation"""
        # Valid tokens
        self.assertTrue(self.security_manager.validate_api_token("valid_token_12345"))
        self.assertTrue(self.security_manager.validate_api_token("api-key-with-dashes"))

        # Invalid tokens
        self.assertFalse(self.security_manager.validate_api_token(""))
        self.assertFalse(self.security_manager.validate_api_token("short"))
        self.assertFalse(
            self.security_manager.validate_api_token("a" * 200)
        )  # Too long
        self.assertFalse(self.security_manager.validate_api_token("invalid@token"))

    def test_generate_secure_filename(self):
        """Test secure filename generation"""
        dangerous_name = 'file<>:"/\\|?*.txt'
        secure_name = self.security_manager.generate_secure_filename(dangerous_name)

        # Should not contain dangerous characters
        self.assertNotIn("<", secure_name)
        self.assertNotIn(">", secure_name)
        self.assertNotIn(":", secure_name)
        self.assertNotIn('"', secure_name)
        self.assertNotIn("/", secure_name)
        self.assertNotIn("\\", secure_name)
        self.assertNotIn("|", secure_name)
        self.assertNotIn("?", secure_name)
        self.assertNotIn("*", secure_name)

        # Should have random suffix
        self.assertIn("_", secure_name)

    def test_hash_sensitive_data(self):
        """Test hashing of sensitive data"""
        data = "password123"
        hashed = self.security_manager.hash_sensitive_data(data)

        self.assertIsInstance(hashed, str)
        self.assertEqual(len(hashed), 64)  # SHA256 hex length
        self.assertNotEqual(hashed, data)


class TestInputValidation(unittest.TestCase):
    """Test input validation security"""

    def test_validate_input_security_general(self):
        """Test general input validation"""
        # Valid inputs
        result = validate_input_security("normal_input")
        self.assertTrue(result["valid"])

        # Empty input
        result = validate_input_security("")
        self.assertFalse(result["valid"])
        self.assertIn("empty", result["reason"])

        # Whitespace only
        result = validate_input_security("   ")
        self.assertFalse(result["valid"])

    def test_validate_input_security_injection_patterns(self):
        """Test injection pattern detection"""
        dangerous_inputs = [
            "test; rm -rf /",
            "test && cat /etc/passwd",
            "test | whoami",
            "test `id`",
            "test $(whoami)",
            "test{command}",
            "test..//etc/passwd",
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
        ]

        for dangerous_input in dangerous_inputs:
            result = validate_input_security(dangerous_input)
            self.assertFalse(
                result["valid"],
                f"Failed to detect dangerous pattern: {dangerous_input}",
            )
            self.assertIn("dangerous", result["reason"])

    def test_validate_input_security_ip(self):
        """Test IP address validation"""
        # Valid IPs
        valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
        for ip in valid_ips:
            result = validate_input_security(ip, "ip")
            self.assertTrue(result["valid"], f"Valid IP rejected: {ip}")

        # Invalid IPs
        invalid_ips = ["256.1.2.3", "1.2.3.256", "192.168.1", "invalid"]
        for ip in invalid_ips:
            result = validate_input_security(ip, "ip")
            self.assertFalse(result["valid"], f"Invalid IP accepted: {ip}")

    def test_validate_input_security_url(self):
        """Test URL validation"""
        # Valid URLs
        valid_urls = [
            "https://example.com",
            "http://example.com",
            "https://example.com:8080",
            "https://example.com/path",
        ]
        for url in valid_urls:
            result = validate_input_security(url, "url")
            self.assertTrue(result["valid"], f"Valid URL rejected: {url}")

        # Invalid URLs
        invalid_urls = ["not-a-url", "ftp://example.com", "javascript:alert('xss')"]
        for url in invalid_urls:
            result = validate_input_security(url, "url")
            self.assertFalse(result["valid"], f"Invalid URL accepted: {url}")

    def test_validate_input_security_length_limits(self):
        """Test input length limits"""
        # Test maximum length
        long_input = "a" * 1001
        result = validate_input_security(long_input)
        self.assertFalse(result["valid"])
        self.assertIn("too long", result["reason"])

        # Test acceptable length
        acceptable_input = "a" * 1000
        result = validate_input_security(acceptable_input)
        self.assertTrue(result["valid"])


if __name__ == "__main__":
    unittest.main()
