"""
Unit tests for core functionality

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import unittest
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import (
    validate_ip_address,
    validate_url,
    validate_domain,
    sanitize_filename,
)
from core.signature import verify_leegion_ownership, generate_leegion_watermark


class TestCoreUtils(unittest.TestCase):
    """Test core utility functions"""

    def test_validate_ip_address(self):
        """Test IP address validation"""
        # Valid IPs
        self.assertTrue(validate_ip_address("192.168.1.1"))
        self.assertTrue(validate_ip_address("10.0.0.1"))
        self.assertTrue(validate_ip_address("172.16.0.1"))
        self.assertTrue(validate_ip_address("127.0.0.1"))

        # Invalid IPs
        self.assertFalse(validate_ip_address("256.1.2.3"))
        self.assertFalse(validate_ip_address("1.2.3.256"))
        self.assertFalse(validate_ip_address("192.168.1"))
        self.assertFalse(validate_ip_address("192.168.1.1.1"))
        self.assertFalse(validate_ip_address("invalid"))
        self.assertFalse(validate_ip_address(""))

    def test_validate_url(self):
        """Test URL validation"""
        # Valid URLs
        self.assertTrue(validate_url("https://example.com"))
        self.assertTrue(validate_url("http://example.com"))
        self.assertTrue(validate_url("https://example.com:8080"))
        self.assertTrue(validate_url("https://example.com/path"))
        self.assertTrue(validate_url("https://example.com/path?param=value"))

        # Invalid URLs
        self.assertFalse(validate_url("not-a-url"))
        self.assertFalse(validate_url("ftp://example.com"))
        self.assertFalse(validate_url(""))

    def test_validate_domain(self):
        """Test domain validation"""
        # Valid domains
        self.assertTrue(validate_domain("example.com"))
        self.assertTrue(validate_domain("sub.example.com"))
        self.assertTrue(validate_domain("example.co.uk"))

        # Invalid domains
        self.assertFalse(validate_domain("example"))
        self.assertFalse(validate_domain(""))
        self.assertFalse(validate_domain("example..com"))

    def test_sanitize_filename(self):
        """Test filename sanitization"""
        # Test invalid characters
        self.assertEqual(sanitize_filename('file<>:"/\\|?*.txt'), "file_________.txt")

        # Test leading/trailing dots and spaces
        self.assertEqual(sanitize_filename("  .file.txt.  "), "file.txt")

        # Test length limit
        long_name = "a" * 300
        sanitized = sanitize_filename(long_name)
        self.assertLessEqual(len(sanitized), 200)

        # Test empty result
        self.assertEqual(sanitize_filename(""), "unnamed_file")


class TestSignature(unittest.TestCase):
    """Test signature and ownership verification"""

    def test_verify_leegion_ownership(self):
        """Test ownership verification"""
        ownership = verify_leegion_ownership()

        self.assertIn("author", ownership)
        self.assertIn("project", ownership)
        self.assertIn("framework_id", ownership)
        self.assertEqual(ownership["author"], "Leegion")
        self.assertEqual(ownership["project"], "Leegion Framework v2.0")

    def test_generate_leegion_watermark(self):
        """Test watermark generation"""
        watermark = generate_leegion_watermark()

        self.assertIsInstance(watermark, str)
        self.assertIn("LEEGION-WATERMARK", watermark)


if __name__ == "__main__":
    unittest.main()
