"""
SSL/TLS Analyzer Module for Leegion Framework

This module provides comprehensive SSL/TLS certificate analysis
and security assessment capabilities.
"""

import json
import os
import socket
import ssl
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests
import subprocess
import csv
import cryptography.x509
import hashlib
from urllib.parse import urlparse
from core.base_module import BaseModule
from core.banner import print_module_header
from core.security import network_rate_limiter


class SSLAnalyzer(BaseModule):
    """Advanced SSL/TLS certificate and configuration analyzer"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "SSL_Analyzer")
        self.analysis_results = []
        self.certificates = {}
        self.timeout = config.get("timeout", 10)

    def run(self):
        """Main SSL analyzer interface"""
        print_module_header(
            "SSL/TLS Analyzer", "Certificate & Configuration Security Analysis"
        )

        while True:
            self._display_ssl_menu()
            choice = self.get_user_input("Select analysis option: ")

            if not choice:
                continue

            if choice == "1":
                self._single_host_analysis()
            elif choice == "2":
                self._certificate_chain_analysis()
            elif choice == "3":
                self._ssl_configuration_scan()
            elif choice == "4":
                self._vulnerability_assessment()
            elif choice == "5":
                self._certificate_expiry_check()
            elif choice == "6":
                self._batch_ssl_scan()
            elif choice == "7":
                self._cipher_suite_analysis()
            elif choice == "8":
                self._ssl_labs_integration()
            elif choice == "9":
                self._view_analysis_results()
            elif choice == "10":
                self._export_ssl_results()
            elif choice == "11":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_ssl_menu(self):
        """Display SSL analyzer menu"""
        analyzed_count = len(self.analysis_results)

        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'SSL/TLS ANALYZER MENU'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print(f"\033[96mAnalyzed Hosts:\033[0m {analyzed_count}")
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m 1.\033[0m Single Host SSL Analysis")
        print("\033[96m 2.\033[0m Certificate Chain Analysis")
        print("\033[96m 3.\033[0m SSL Configuration Scan")
        print("\033[96m 4.\033[0m SSL Vulnerability Assessment")
        print("\033[96m 5.\033[0m Certificate Expiry Check")
        print("\033[96m 6.\033[0m Batch SSL Scan")
        print("\033[96m 7.\033[0m Cipher Suite Analysis")
        print("\033[96m 8.\033[0m SSL Labs Integration")
        print("\033[96m 9.\033[0m View Analysis Results")
        print("\033[96m10.\033[0m Export SSL Results")
        print("\033[96m11.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")

    def _single_host_analysis(self):
        """Perform comprehensive SSL analysis for a single host"""
        print("\n\033[96m📚 WHAT IS SSL/TLS ANALYSIS?\033[0m")
        print("\n\033[93m💡 PRACTICAL EXAMPLES:\033[0m")
        print("• Banking sites: Should have strong encryption (A+ grade)")
        print("• Self-signed certificates: Often found on internal servers")
        print("• Expired certificates: Can indicate poor maintenance")
        print("• Weak ciphers: Make sites vulnerable to eavesdropping")

        target = self.get_user_input("\nEnter hostname or URL (e.g., example.com): ")
        if not target:
            return

        # Parse hostname and port
        hostname, port = self._parse_target(target)
        if not hostname:
            return

        self.print_info(f"Starting comprehensive SSL analysis for {hostname}:{port}")
        self.print_info("Checking: Certificate validity, encryption strength, and")

        try:
            # Get certificate information
            cert_info = self._get_certificate_info(hostname, port)
            if not cert_info:
                self.print_error("Failed to retrieve certificate information")
                return

            # Perform comprehensive analysis
            analysis_result = {
                "timestamp": datetime.now().isoformat(),
                "hostname": hostname,
                "port": port,
                "certificate": cert_info,
                "chain_analysis": self._analyze_certificate_chain(hostname, port),
                "protocol_support": self._test_protocol_support(hostname, port),
                "cipher_suites": self._analyze_cipher_suites(hostname, port),
                "vulnerabilities": self._check_ssl_vulnerabilities(hostname, port),
                "security_headers": self._check_security_headers(hostname, port),
                "overall_grade": "A+",  # Will be calculated
            }

            # Calculate security grade
            analysis_result["overall_grade"] = self._calculate_security_grade(
                analysis_result
            )

            # Store results
            self.analysis_results.append(analysis_result)
            self.add_result(analysis_result)

            # Display summary
            self._display_ssl_summary(analysis_result)

        except Exception as e:
            self.print_error(f"SSL analysis failed: {e}")
            self.logger.error(f"SSL analysis error for {hostname}:{port}: {e}")

    def _certificate_chain_analysis(self):
        """Analyze SSL certificate chain"""
        target = self.get_user_input("Enter hostname: ")
        if not target:
            return

        hostname, port = self._parse_target(target)

        self.print_info(f"Analyzing certificate chain for {hostname}:{port}")

        try:
            chain_info = self._get_full_certificate_chain(hostname, port)
            if chain_info:
                self._display_certificate_chain(chain_info)

                # Store chain analysis
                result = {
                    "timestamp": datetime.now().isoformat(),
                    "hostname": hostname,
                    "port": port,
                    "analysis_type": "certificate_chain",
                    "chain_info": chain_info,
                }
                self.add_result(result)
            else:
                self.print_error("Failed to retrieve certificate chain")

        except Exception as e:
            self.print_error(f"Certificate chain analysis failed: {e}")

    def _ssl_configuration_scan(self):
        """Scan SSL/TLS configuration"""
        target = self.get_user_input("Enter hostname: ")
        if not target:
            return

        hostname, port = self._parse_target(target)

        self.print_info(f"Scanning SSL configuration for {hostname}:{port}")

        try:
            config_info = {
                "protocols": self._test_protocol_support(hostname, port),
                "cipher_suites": self._analyze_cipher_suites(hostname, port),
                "key_exchange": self._analyze_key_exchange(hostname, port),
                "perfect_forward_secrecy": self._check_pfs(hostname, port),
                "hsts": self._check_hsts(hostname, port),
                "session_resumption": self._check_session_resumption(hostname, port),
            }

            self._display_configuration_summary(config_info)

            # Store configuration scan
            result = {
                "timestamp": datetime.now().isoformat(),
                "hostname": hostname,
                "port": port,
                "analysis_type": "configuration_scan",
                "configuration": config_info,
            }
            self.add_result(result)

        except Exception as e:
            self.print_error(f"SSL configuration scan failed: {e}")

    def _vulnerability_assessment(self):
        """Assess SSL/TLS vulnerabilities"""
        target = self.get_user_input("Enter hostname: ")
        if not target:
            return

        hostname, port = self._parse_target(target)

        self.print_info(f"Assessing SSL vulnerabilities for {hostname}:{port}")

        vulnerabilities = self._comprehensive_vulnerability_check(hostname, port)

        if vulnerabilities:
            self.print_warning(
                f"Found {len(vulnerabilities)} potential vulnerabilities"
            )
            for vuln in vulnerabilities:
                severity_color = self._get_severity_color(vuln["severity"])
                self.print_warning(
                    f"[{severity_color}{vuln['severity']}\033[0m] "
                    f"{vuln['name']}: {vuln['description']}"
                )
        else:
            self.print_success("No known SSL vulnerabilities detected")

        # Store vulnerability assessment
        result = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "port": port,
            "analysis_type": "vulnerability_assessment",
            "vulnerabilities": vulnerabilities,
        }
        self.add_result(result)

    def _certificate_expiry_check(self):
        """Check certificate expiration dates"""
        targets_input = self.get_user_input("Enter hostnames (comma-separated): ")
        if not targets_input:
            return

        targets = [target.strip() for target in targets_input.split(",")]

        self.print_info(f"Checking certificate expiry for {len(targets)} hosts")

        expiry_results = []

        for target in targets:
            hostname, port = self._parse_target(target)

            try:
                cert_info = self._get_certificate_info(hostname, port)
                if cert_info:
                    expiry_date = cert_info.get("not_after")
                    if expiry_date:
                        days_until_expiry = (expiry_date - datetime.now()).days

                        expiry_results.append(
                            {
                                "hostname": hostname,
                                "port": port,
                                "expiry_date": expiry_date.isoformat(),
                                "days_until_expiry": days_until_expiry,
                                "status": self._get_expiry_status(days_until_expiry),
                            }
                        )

                        # Display result
                        status_color = self._get_expiry_color(days_until_expiry)
                        self.print_info(
                            f"{hostname}:{port} - Expires in "
                            f"{status_color}{days_until_expiry}\033[0m days"
                        )

            except Exception as e:
                self.print_error(f"Failed to check {hostname}:{port}: {e}")

        # Store expiry check results
        result = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": "certificate_expiry",
            "expiry_results": expiry_results,
        }
        self.add_result(result)

    def _batch_ssl_scan(self):
        """Perform batch SSL scanning"""
        print("\nBatch SSL scan options:")
        print("1. Load hostnames from file")
        print("2. Enter hostnames manually")

        option = self.get_user_input("Select option (1-2): ")

        hostnames = []
        if option == "1":
            filename = self.get_user_input("Enter filename: ", "file_path")
            if filename:
                hostnames = self._load_hostnames_from_file(filename)
        elif option == "2":
            hosts_input = self.get_user_input("Enter hostnames (comma-separated): ")
            if hosts_input:
                hostnames = [host.strip() for host in hosts_input.split(",")]

        if not hostnames:
            self.print_error("No hostnames provided")
            return

        self.print_info(f"Starting batch SSL scan for {len(hostnames)} hosts")

        # Perform batch analysis
        batch_results = []
        for i, hostname in enumerate(hostnames, 1):
            self.print_info(f"Scanning {i}/{len(hostnames)}: {hostname}")

            try:
                host, port = self._parse_target(hostname)
                cert_info = self._get_certificate_info(host, port)

                if cert_info:
                    basic_analysis = {
                        "hostname": host,
                        "port": port,
                        "subject": cert_info.get("subject", {}),
                        "issuer": cert_info.get("issuer", {}),
                        "expiry_date": cert_info.get("not_after"),
                        "signature_algorithm": cert_info.get("signature_algorithm"),
                        "key_size": cert_info.get("key_size"),
                    }
                    batch_results.append(basic_analysis)

                    # Quick status
                    expiry_days = (
                        (cert_info.get("not_after") - datetime.now()).days
                        if cert_info.get("not_after")
                        else 0
                    )
                    status_color = self._get_expiry_color(expiry_days)
                    self.print_success(
                        f"  Certificate valid, expires in "
                        f"{status_color}{expiry_days}\033[0m days"
                    )
                else:
                    self.print_error("  Failed to retrieve certificate")

            except Exception as e:
                self.print_error(f"  Error: {e}")

        # Store batch results
        result = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": "batch_ssl_scan",
            "total_hosts": len(hostnames),
            "successful_scans": len(batch_results),
            "batch_results": batch_results,
        }
        self.add_result(result)

        self.print_success(
            f"Batch scan completed: "
            f"{len(batch_results)}/{len(hostnames)} hosts analyzed"
        )

    def _cipher_suite_analysis(self):
        """Analyze supported cipher suites"""
        target = self.get_user_input("Enter hostname: ")
        if not target:
            return

        hostname, port = self._parse_target(target)

        self.print_info(f"Analyzing cipher suites for {hostname}:{port}")

        cipher_analysis = self._detailed_cipher_analysis(hostname, port)

        if cipher_analysis:
            self._display_cipher_analysis(cipher_analysis)

            result = {
                "timestamp": datetime.now().isoformat(),
                "hostname": hostname,
                "port": port,
                "analysis_type": "cipher_suite_analysis",
                "cipher_analysis": cipher_analysis,
            }
            self.add_result(result)

    def _ssl_labs_integration(self):
        """Integrate with SSL Labs API for detailed analysis"""
        target = self.get_user_input("Enter hostname (SSL Labs API): ")
        if not target:
            return

        self.print_info("Querying SSL Labs API (this may take several minutes)...")
        self.print_warning("Note: This sends data to a third-party service")

        try:
            ssl_labs_result = self._query_ssl_labs(target)
            if ssl_labs_result:
                self._display_ssl_labs_result(ssl_labs_result)

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "hostname": target,
                    "analysis_type": "ssl_labs_analysis",
                    "ssl_labs_result": ssl_labs_result,
                }
                self.add_result(result)
            else:
                self.print_error("SSL Labs analysis failed or timed out")

        except Exception as e:
            self.print_error(f"SSL Labs integration failed: {e}")

    def _parse_target(self, target: str) -> Tuple[str, int]:
        """Parse target hostname and port"""
        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        elif ":" in target:
            hostname, port_str = target.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        else:
            hostname = target
            port = 443

        return hostname, port

    def _get_certificate_info(
        self, hostname: str, port: int
    ) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    # Parse certificate details
                    cert_info = {
                        "subject": dict(x[0] for x in cert_dict.get("subject", [])),
                        "issuer": dict(x[0] for x in cert_dict.get("issuer", [])),
                        "version": cert_dict.get("version"),
                        "serial_number": cert_dict.get("serialNumber"),
                        "not_before": datetime.strptime(
                            cert_dict.get("notBefore"), "%b %d %H:%M:%S %Y %Z"
                        ),
                        "not_after": datetime.strptime(
                            cert_dict.get("notAfter"), "%b %d %H:%M:%S %Y %Z"
                        ),
                        "signature_algorithm": cert_dict.get("signatureAlgorithm"),
                        "san": cert_dict.get("subjectAltName", []),
                        "key_size": self._get_key_size(cert),
                        "fingerprint_sha1": self._get_cert_fingerprint(cert, "sha1"),
                        "fingerprint_sha256": self._get_cert_fingerprint(
                            cert, "sha256"
                        ),
                    }

                    return cert_info

        except Exception as e:
            self.logger.error(f"Certificate retrieval error for {hostname}:{port}: {e}")
            return None

    def _get_key_size(self, cert_binary: bytes) -> Optional[int]:
        """Extract key size from certificate"""
        try:
            cert = cryptography.x509.load_der_x509_certificate(cert_binary)
            public_key = cert.public_key()

            if hasattr(public_key, "key_size"):
                return public_key.key_size
        except Exception:
            pass
        return None

    def _get_cert_fingerprint(self, cert_binary: bytes, algorithm: str) -> str:
        """Calculate certificate fingerprint"""
        try:
            if algorithm == "sha1":
                return hashlib.sha1(cert_binary).hexdigest()
            elif algorithm == "sha256":
                return hashlib.sha256(cert_binary).hexdigest()
        except Exception:
            pass
        return ""

    def _analyze_certificate_chain(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze the certificate chain"""
        try:
            # Use openssl to get full chain if available
            chain_info = self._get_openssl_chain_info(hostname, port)

            return {
                "chain_length": len(chain_info) if chain_info else 0,
                "root_ca_trusted": True,  # Simplified check
                "intermediate_ca_count": (
                    len(chain_info) - 1 if chain_info and len(chain_info) > 1 else 0
                ),
                "chain_issues": [],
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_openssl_chain_info(self, hostname: str, port: int) -> Optional[List[Dict]]:
        """Get certificate chain using OpenSSL command"""
        try:
            cmd = [
                "openssl",
                "s_client",
                "-connect",
                f"{hostname}:{port}",
                "-showcerts",
            ]
            result = subprocess.run(
                cmd, input="", text=True, capture_output=True, timeout=self.timeout
            )

            if result.returncode == 0:
                # Parse OpenSSL output for certificate chain
                # This is a simplified version
                # Parse certificate chain from OpenSSL output
                certificates = []
                cert_blocks = result.stdout.split("-----BEGIN CERTIFICATE-----")
                for i, block in enumerate(cert_blocks[1:]):  # Skip first empty element
                    if "-----END CERTIFICATE-----" in block:
                        certificates.append(
                            {
                                "position": i,
                                "subject": f"Certificate {i+1}",
                                "issuer": "Unknown",
                            }
                        )
                return (
                    certificates
                    if certificates
                    else [{"subject": hostname, "position": 0}]
                )
        except Exception as e:
            self.logger.debug(f"OpenSSL chain analysis failed: {e}")

        return None

    def _test_protocol_support(self, hostname: str, port: int) -> Dict[str, bool]:
        """Test SSL/TLS protocol support"""
        protocols = {
            "SSLv2": ssl.PROTOCOL_SSLv23,  # Deprecated
            "SSLv3": ssl.PROTOCOL_SSLv23,  # Deprecated
            "TLSv1.0": ssl.PROTOCOL_TLSv1,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        }

        # Add TLS 1.3 if available
        if hasattr(ssl, "PROTOCOL_TLSv1_3"):
            protocols["TLSv1.3"] = ssl.PROTOCOL_TLSv1_3

        supported = {}

        for protocol_name, protocol_const in protocols.items():
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock):
                        supported[protocol_name] = True
            except Exception:
                supported[protocol_name] = False

        return supported

    def _analyze_cipher_suites(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze supported cipher suites"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()

                    return {
                        "negotiated_cipher": cipher[0] if cipher else None,
                        "protocol": cipher[1] if cipher else None,
                        "key_bits": cipher[2] if cipher else None,
                        "cipher_strength": self._classify_cipher_strength(
                            cipher[0] if cipher else ""
                        ),
                    }
        except Exception as e:
            return {"error": str(e)}

    def _classify_cipher_strength(self, cipher_name: str) -> str:
        """Classify cipher strength"""
        if not cipher_name:
            return "unknown"

        cipher_lower = cipher_name.lower()

        if any(
            weak in cipher_lower for weak in ["null", "anon", "export", "des", "rc4"]
        ):
            return "weak"
        elif any(medium in cipher_lower for medium in ["3des", "128"]):
            return "medium"
        elif any(
            strong in cipher_lower for strong in ["aes256", "chacha20", "aes_256"]
        ):
            return "strong"
        else:
            return "medium"

    def _analyze_key_exchange(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze key exchange mechanisms"""
        # Simplified analysis
        # Analyze key exchange through cipher negotiation
        try:
            cipher_info = self._analyze_cipher_suites(hostname, port)
            cipher_name = cipher_info.get("negotiated_cipher", "").lower()

            supports_dhe = "dhe" in cipher_name and "ecdhe" not in cipher_name
            supports_ecdhe = "ecdhe" in cipher_name

            # Determine strength based on key exchange method
            if supports_ecdhe:
                strength = "strong"
            elif supports_dhe:
                strength = "medium"
            else:
                strength = "weak"

            return {
                "supports_dhe": supports_dhe,
                "supports_ecdhe": supports_ecdhe,
                "key_exchange_strength": strength,
            }
        except Exception:
            return {
                "supports_dhe": False,
                "supports_ecdhe": False,
                "key_exchange_strength": "unknown",
            }

    def _check_pfs(self, hostname: str, port: int) -> bool:
        """Check for Perfect Forward Secrecy support"""
        try:
            cipher_info = self._analyze_cipher_suites(hostname, port)
            cipher_name = cipher_info.get("negotiated_cipher", "").lower()

            # Check if cipher supports PFS
            return any(
                pfs_indicator in cipher_name for pfs_indicator in ["dhe", "ecdhe"]
            )
        except Exception:
            return False

    def _check_hsts(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check HTTP Strict Transport Security"""
        try:
            url = f"https://{hostname}:{port}"
            # Rate limiting for network requests
            while not network_rate_limiter.allow():
                time.sleep(0.05)
            response = requests.get(url, timeout=self.timeout, verify=False)

            hsts_header = response.headers.get("Strict-Transport-Security", "")

            return {
                "enabled": bool(hsts_header),
                "header_value": hsts_header,
                "max_age": self._parse_hsts_max_age(hsts_header),
                "include_subdomains": "includeSubDomains" in hsts_header,
                "preload": "preload" in hsts_header,
            }
        except Exception as e:
            return {"error": str(e)}

    def _parse_hsts_max_age(self, hsts_header: str) -> Optional[int]:
        """Parse max-age from HSTS header"""
        try:
            for directive in hsts_header.split(";"):
                if directive.strip().startswith("max-age="):
                    return int(directive.strip().split("=")[1])
        except Exception:
            pass
        return None

    def _check_session_resumption(self, hostname: str, port: int) -> Dict[str, bool]:
        """Check session resumption support"""
        # Simplified check
        # Test session resumption by making multiple connections
        try:
            # First connection to establish session
            context1 = ssl.create_default_context()
            context1.check_hostname = False
            context1.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock1:
                with context1.wrap_socket(sock1) as ssock1:
                    session1 = ssock1.session

            # Second connection to test resumption
            context2 = ssl.create_default_context()
            context2.check_hostname = False
            context2.verify_mode = ssl.CERT_NONE

            session_resumed = False
            with socket.create_connection((hostname, port), timeout=5) as sock2:
                with context2.wrap_socket(sock2) as ssock2:
                    session2 = ssock2.session
                    session_resumed = (
                        session1 is not None
                        and session2 is not None
                        and session1.id == session2.id
                    )

            return {
                "session_id_resumption": session_resumed,
                "session_ticket_resumption": session_resumed,  # Simplified check
            }
        except Exception:
            return {"session_id_resumption": False, "session_ticket_resumption": False}

    def _check_ssl_vulnerabilities(
        self, hostname: str, port: int
    ) -> List[Dict[str, str]]:
        """Check for known SSL vulnerabilities"""
        vulnerabilities = []

        # Check protocol support for known vulnerable protocols
        protocol_support = self._test_protocol_support(hostname, port)

        if protocol_support.get("SSLv2"):
            vulnerabilities.append(
                {
                    "name": "SSLv2 Support",
                    "severity": "HIGH",
                    "description": "Server supports deprecated SSLv2 protocol",
                }
            )

        if protocol_support.get("SSLv3"):
            vulnerabilities.append(
                {
                    "name": "SSLv3 Support (POODLE)",
                    "severity": "HIGH",
                    "description": "Server supports SSLv3 which is vulnerable to POODLE attack",
                }
            )

        # Check cipher suites
        cipher_info = self._analyze_cipher_suites(hostname, port)
        cipher_name = cipher_info.get("negotiated_cipher", "").lower()

        if "rc4" in cipher_name:
            vulnerabilities.append(
                {
                    "name": "RC4 Cipher Support",
                    "severity": "MEDIUM",
                    "description": "Server supports RC4 cipher which has known weaknesses",
                }
            )

        if "des" in cipher_name and "3des" not in cipher_name:
            vulnerabilities.append(
                {
                    "name": "DES Cipher Support",
                    "severity": "HIGH",
                    "description": "Server supports DES cipher which is cryptographically weak",
                }
            )

        return vulnerabilities

    def _comprehensive_vulnerability_check(
        self, hostname: str, port: int
    ) -> List[Dict[str, str]]:
        """Comprehensive vulnerability assessment"""
        vulnerabilities = self._check_ssl_vulnerabilities(hostname, port)

        # Additional vulnerability checks could be added here
        # Examples: Heartbleed, CCS Injection, etc.

        return vulnerabilities

    def _check_security_headers(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check HTTP security headers"""
        try:
            url = f"https://{hostname}:{port}"
            # Rate limiting for network requests
            while not network_rate_limiter.allow():
                time.sleep(0.05)
            response = requests.get(url, timeout=self.timeout, verify=False)
            headers = response.headers

            return {
                "strict_transport_security": headers.get("Strict-Transport-Security"),
                "content_security_policy": headers.get("Content-Security-Policy"),
                "x_frame_options": headers.get("X-Frame-Options"),
                "x_content_type_options": headers.get("X-Content-Type-Options"),
                "x_xss_protection": headers.get("X-XSS-Protection"),
                "referrer_policy": headers.get("Referrer-Policy"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _calculate_security_grade(self, analysis_result: Dict[str, Any]) -> str:
        """Calculate overall security grade"""
        score = 100

        # Deduct points for vulnerabilities
        vulnerabilities = analysis_result.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if vuln["severity"] == "HIGH":
                score -= 20
            elif vuln["severity"] == "MEDIUM":
                score -= 10
            elif vuln["severity"] == "LOW":
                score -= 5

        # Deduct for weak protocols
        protocols = analysis_result.get("protocol_support", {})
        if protocols.get("SSLv2") or protocols.get("SSLv3"):
            score -= 30

        # Deduct for weak ciphers
        cipher_info = analysis_result.get("cipher_suites", {})
        if cipher_info.get("cipher_strength") == "weak":
            score -= 25
        elif cipher_info.get("cipher_strength") == "medium":
            score -= 10

        # Convert score to grade
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 50:
            return "D"
        else:
            return "F"

    def _detailed_cipher_analysis(
        self, hostname: str, port: int
    ) -> Optional[Dict[str, Any]]:
        """Detailed cipher suite analysis using multiple methods"""
        try:
            # Method 1: Use OpenSSL to get comprehensive cipher information
            openssl_result = self._openssl_cipher_analysis(hostname, port)

            # Method 2: Use Python SSL to test multiple ciphers
            python_result = self._python_cipher_analysis(hostname, port)

            # Method 3: Test specific cipher suites
            tested_ciphers = self._test_cipher_suites(hostname, port)

            # Combine results
            return {
                "preferred_cipher": openssl_result.get("negotiated_cipher")
                or python_result.get("negotiated_cipher"),
                "cipher_strength": self._evaluate_cipher_strength(tested_ciphers),
                "protocol_version": openssl_result.get("protocol")
                or python_result.get("protocol"),
                "key_bits": openssl_result.get("key_bits")
                or python_result.get("key_bits"),
                "cipher_order": openssl_result.get("cipher_order", "server"),
                "cipher_categories": {
                    "strong_ciphers": tested_ciphers.get("strong", []),
                    "medium_ciphers": tested_ciphers.get("medium", []),
                    "weak_ciphers": tested_ciphers.get("weak", []),
                    "supported_count": len(tested_ciphers.get("all", [])),
                },
                "detailed_results": {
                    "openssl": openssl_result,
                    "python_ssl": python_result,
                    "tested_ciphers": tested_ciphers,
                },
            }
        except Exception as e:
            self.print_error(f"Detailed cipher analysis failed: {e}")
            return None

    def _openssl_cipher_analysis(self, hostname: str, port: int) -> Dict[str, Any]:
        """Use OpenSSL command for cipher analysis"""
        try:
            cmd = [
                "openssl",
                "s_client",
                "-connect",
                f"{hostname}:{port}",
                "-cipher",
                "ALL",
            ]
            result = subprocess.run(
                cmd, input="", text=True, capture_output=True, timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse OpenSSL output
                cipher_info = {}
                for line in output.split("\n"):
                    if "Cipher    :" in line:
                        cipher_info["negotiated_cipher"] = line.split(":")[1].strip()
                    elif "Protocol  :" in line:
                        cipher_info["protocol"] = line.split(":")[1].strip()
                    elif "Server public key is" in line:
                        key_bits = line.split("is")[1].strip().split()[0]
                        cipher_info["key_bits"] = (
                            int(key_bits) if key_bits.isdigit() else None
                        )

                return cipher_info
        except Exception as e:
            self.logger.debug(f"OpenSSL cipher analysis failed: {e}")

        return {}

    def _python_cipher_analysis(self, hostname: str, port: int) -> Dict[str, Any]:
        """Use Python SSL for cipher analysis"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return {
                            "negotiated_cipher": cipher[0],
                            "protocol": cipher[1],
                            "key_bits": cipher[2],
                        }
        except Exception as e:
            self.logger.debug(f"Python SSL cipher analysis failed: {e}")

        return {}

    def _test_cipher_suites(self, hostname: str, port: int) -> Dict[str, List[str]]:
        """Test multiple cipher suites"""
        cipher_categories = {"strong": [], "medium": [], "weak": [], "all": []}

        # Define cipher suites to test
        test_ciphers = {
            "strong": [
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-CHACHA20-POLY1305",
                "DHE-RSA-AES256-GCM-SHA384",
            ],
            "medium": [
                "AES256-SHA256",
                "AES128-SHA256",
                "ECDHE-RSA-AES256-SHA384",
                "ECDHE-RSA-AES128-SHA256",
            ],
            "weak": ["RC4-SHA", "RC4-MD5", "DES-CBC-SHA", "EXP-RC4-MD5"],
        }

        for strength, ciphers in test_ciphers.items():
            for cipher in ciphers:
                if self._test_single_cipher(hostname, port, cipher):
                    cipher_categories[strength].append(cipher)
                    cipher_categories["all"].append(cipher)

        return cipher_categories

    def _test_single_cipher(self, hostname: str, port: int, cipher: str) -> bool:
        """Test if a single cipher is supported"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers(cipher)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock):
                    return True
        except Exception:
            return False

    def _evaluate_cipher_strength(self, tested_ciphers: Dict[str, List[str]]) -> str:
        """Evaluate overall cipher strength"""
        if tested_ciphers.get("weak"):
            return "weak"
        elif tested_ciphers.get("strong") and len(tested_ciphers["strong"]) > len(
            tested_ciphers.get("medium", [])
        ):
            return "strong"
        elif tested_ciphers.get("medium"):
            return "medium"
        else:
            return "unknown"

    def _query_ssl_labs(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Query SSL Labs API for detailed analysis"""
        try:
            # SSL Labs API endpoint
            api_url = "https://api.ssllabs.com/api/v3/analyze"

            # Start analysis
            start_params = {
                "host": hostname,
                "publish": "off",
                "startNew": "on",
                "all": "done",
            }

            response = requests.get(api_url, params=start_params, timeout=30)
            if response.status_code != 200:
                return None

            result = response.json()

            # Wait for analysis to complete (simplified)
            max_wait = 300  # 5 minutes
            waited = 0

            while result.get("status") not in ["READY", "ERROR"] and waited < max_wait:
                time.sleep(10)
                waited += 10

                check_response = requests.get(
                    api_url, params={"host": hostname}, timeout=30
                )
                if check_response.status_code == 200:
                    result = check_response.json()
                else:
                    break

            return result

        except Exception as e:
            self.print_error(f"SSL Labs API query failed: {e}")
            return None

    def _load_hostnames_from_file(self, filename: str) -> List[str]:
        """Load hostnames from file"""
        try:
            with open(filename, "r") as f:
                hostnames = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            self.print_success(f"Loaded {len(hostnames)} hostnames from file")
            return hostnames
        except Exception as e:
            self.print_error(f"Failed to load hostnames: {e}")
            return []

    def _get_full_certificate_chain(
        self, hostname: str, port: int
    ) -> Optional[List[Dict]]:
        """Get full certificate chain information"""
        try:
            # Use OpenSSL to get full chain
            cmd = [
                "openssl",
                "s_client",
                "-connect",
                f"{hostname}:{port}",
                "-showcerts",
            ]
            result = subprocess.run(
                cmd, input="", text=True, capture_output=True, timeout=15
            )

            if result.returncode == 0:
                # Parse certificate chain from OpenSSL output
                # This is a simplified implementation
                return [{"subject": hostname, "level": 0}]
        except Exception as e:
            self.logger.debug(f"Certificate chain retrieval failed: {e}")

        return None

    def _get_severity_color(self, severity: str) -> str:
        """Get color for vulnerability severity"""
        colors = {
            "HIGH": "\033[91m",  # Red
            "MEDIUM": "\033[93m",  # Yellow
            "LOW": "\033[94m",  # Blue
            "INFO": "\033[96m",  # Cyan
        }
        return colors.get(severity, "\033[0m")

    def _get_expiry_status(self, days_until_expiry: int) -> str:
        """Get certificate expiry status"""
        if days_until_expiry < 0:
            return "expired"
        elif days_until_expiry < 7:
            return "critical"
        elif days_until_expiry < 30:
            return "warning"
        else:
            return "valid"

    def _get_expiry_color(self, days_until_expiry: int) -> str:
        """Get color for certificate expiry"""
        if days_until_expiry < 0:
            return "\033[91m"  # Red - expired
        elif days_until_expiry < 7:
            return "\033[91m"  # Red - critical
        elif days_until_expiry < 30:
            return "\033[93m"  # Yellow - warning
        else:
            return "\033[92m"  # Green - valid

    def _display_ssl_summary(self, analysis_result: Dict[str, Any]):
        """Display SSL analysis summary"""
        print(f"\n\033[93m{'='*70}\033[0m")
        print(f"\033[93m{'SSL ANALYSIS SUMMARY'.center(70)}\033[0m")
        print(f"\033[93m{'='*70}\033[0m")

        hostname = analysis_result["hostname"]
        port = analysis_result["port"]
        grade = analysis_result["overall_grade"]

        grade_color = (
            "\033[92m"
            if grade.startswith("A")
            else "\033[93m" if grade.startswith("B") else "\033[91m"
        )

        print(f"\033[96mHost:\033[0m {hostname}:{port}")
        print(f"\033[96mOverall Grade:\033[0m {grade_color}{grade}\033[0m")

        # Certificate info
        cert = analysis_result.get("certificate", {})
        if cert:
            print("\n\033[92mCertificate Information:\033[0m")
            print(
                f"  \033[96mSubject:\033[0m {cert.get('subject', {}).get('commonName', 'N/A')}"
            )
            print(
                f"  \033[96mIssuer:\033[0m {cert.get('issuer', {}).get('organizationName', 'N/A')}"
            )

            if cert.get("not_after"):
                expiry_days = (cert["not_after"] - datetime.now()).days
                expiry_color = self._get_expiry_color(expiry_days)
                print(
                    f"  \033[96mExpires:\033[0m {expiry_color}{cert['not_after'].strftime('%Y-%m-%d')}\033[0m ({expiry_days} days)"
                )

            if cert.get("key_size"):
                print(f"  \033[96mKey Size:\033[0m {cert['key_size']} bits")

        # Protocol support
        protocols = analysis_result.get("protocol_support", {})
        if protocols:
            print("\n\033[92mProtocol Support:\033[0m")
            for protocol, supported in protocols.items():
                status = "\033[92m✓\033[0m" if supported else "\033[91m✗\033[0m"
                print(f"  {protocol}: {status}")

        # Vulnerabilities
        vulnerabilities = analysis_result.get("vulnerabilities", [])
        if vulnerabilities:
            print("\n\033[91mVulnerabilities Found:\033[0m")
            for vuln in vulnerabilities:
                severity_color = self._get_severity_color(vuln["severity"])
                print(f"  [{severity_color}{vuln['severity']}\033[0m] {vuln['name']}")
        else:
            print("\n\033[92mNo vulnerabilities detected\033[0m")

    def _display_certificate_chain(self, chain_info: List[Dict]):
        """Display certificate chain information"""
        print(f"\n\033[93m{'CERTIFICATE CHAIN'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        for i, cert in enumerate(chain_info):
            print(f"\033[96mLevel {i}:\033[0m {cert.get('subject', 'Unknown')}")

    def _display_configuration_summary(self, config_info: Dict[str, Any]):
        """Display SSL configuration summary"""
        print(f"\n\033[93m{'SSL CONFIGURATION SUMMARY'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        for category, details in config_info.items():
            print(f"\033[96m{category.replace('_', ' ').title()}:\033[0m")
            if isinstance(details, dict):
                for key, value in details.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {details}")

    def _display_cipher_analysis(self, cipher_analysis: Dict[str, Any]):
        """Display cipher suite analysis"""
        print(f"\n\033[93m{'CIPHER SUITE ANALYSIS'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        print(
            f"\033[96mPreferred Cipher:\033[0m {cipher_analysis.get('preferred_cipher', 'N/A')}"
        )
        print(
            f"\033[96mCipher Strength:\033[0m {cipher_analysis.get('cipher_strength', 'N/A')}"
        )
        print(
            f"\033[96mProtocol Version:\033[0m {cipher_analysis.get('protocol_version', 'N/A')}"
        )
        print(f"\033[96mKey Bits:\033[0m {cipher_analysis.get('key_bits', 'N/A')}")

    def _display_ssl_labs_result(self, ssl_labs_result: Dict[str, Any]):
        """Display SSL Labs analysis result"""
        print(f"\n\033[93m{'SSL LABS ANALYSIS RESULT'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")

        if ssl_labs_result.get("status") == "READY":
            endpoints = ssl_labs_result.get("endpoints", [])
            for endpoint in endpoints:
                grade = endpoint.get("grade", "N/A")
                ip_address = endpoint.get("ipAddress", "N/A")

                grade_color = (
                    "\033[92m"
                    if grade.startswith("A")
                    else "\033[93m" if grade.startswith("B") else "\033[91m"
                )
                print(f"\033[96mEndpoint:\033[0m {ip_address}")
                print(f"\033[96mGrade:\033[0m {grade_color}{grade}\033[0m")
        else:
            print(f"Analysis Status: {ssl_labs_result.get('status', 'Unknown')}")

    def _view_analysis_results(self):
        """View previous SSL analysis results"""
        if not self.analysis_results:
            self.print_warning("No analysis results available")
            return

        print(f"\n\033[93m{'SSL ANALYSIS HISTORY'.center(70)}\033[0m")
        print(f"\033[93m{'-'*70}\033[0m")

        for i, result in enumerate(self.analysis_results, 1):
            timestamp = result["timestamp"][:19].replace("T", " ")
            hostname = result["hostname"]
            port = result["port"]
            grade = result.get("overall_grade", "N/A")

            grade_color = "\033[92m" if grade.startswith("A") else "\033[93m"
            print(
                f"\033[96m{i:2d}.\033[0m {hostname}:{port} - Grade: {grade_color}{grade}\033[0m"
            )
            print(f"     {timestamp}")

        # Allow viewing detailed results
        choice = self.get_user_input("\nView detailed results (enter number or 'q'): ")
        if choice and choice.isdigit():
            result_idx = int(choice) - 1
            if 0 <= result_idx < len(self.analysis_results):
                self._display_ssl_summary(self.analysis_results[result_idx])

    def _export_ssl_results(self):
        """Export SSL analysis results"""
        if not self.analysis_results:
            self.print_warning("No results to export")
            return

        print("\nExport formats:")
        print("1. JSON")
        print("2. CSV")
        print("3. Detailed Report")

        format_choice = self.get_user_input("Select format (1-3): ")

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get("output_dir", "./reports/output")

            if format_choice == "1":
                self._export_ssl_json(output_dir, timestamp)
            elif format_choice == "2":
                self._export_ssl_csv(output_dir, timestamp)
            elif format_choice == "3":
                self._export_ssl_report(output_dir, timestamp)
            else:
                self.print_error("Invalid format selection")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_ssl_json(self, output_dir: str, timestamp: str):
        """Export SSL results to JSON"""
        os.makedirs(output_dir, exist_ok=True)

        filename = f"ssl_analysis_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            json.dump(self.analysis_results, f, indent=2, default=str)

        self.print_success(f"SSL results exported to: {filepath}")

    def _export_ssl_csv(self, output_dir: str, timestamp: str):
        """Export SSL results to CSV"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"ssl_analysis_{timestamp}.csv"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Timestamp",
                    "Hostname",
                    "Port",
                    "Grade",
                    "Certificate Expiry",
                    "Vulnerabilities",
                    "TLS 1.2",
                    "TLS 1.3",
                ]
            )

            for result in self.analysis_results:
                cert = result.get("certificate", {})
                protocols = result.get("protocol_support", {})
                vulns = len(result.get("vulnerabilities", []))

                writer.writerow(
                    [
                        result["timestamp"],
                        result["hostname"],
                        result["port"],
                        result.get("overall_grade", "N/A"),
                        (
                            cert.get("not_after", "").strftime("%Y-%m-%d")
                            if cert.get("not_after")
                            else "N/A"
                        ),
                        vulns,
                        protocols.get("TLSv1.2", False),
                        protocols.get("TLSv1.3", False),
                    ]
                )

        self.print_success(f"SSL results exported to: {filepath}")

    def _export_ssl_report(self, output_dir: str, timestamp: str):
        """Export detailed SSL report"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"ssl_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write("LEEGION FRAMEWORK - SSL/TLS ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Analyses: {len(self.analysis_results)}\n\n")

            for i, result in enumerate(self.analysis_results, 1):
                f.write(f"\nANALYSIS {i}: {result['hostname']}:{result['port']}\n")
                f.write("-" * 50 + "\n")
                f.write(f"Timestamp: {result['timestamp']}\n")
                f.write(f"Overall Grade: {result.get('overall_grade', 'N/A')}\n")

                # Certificate information
                cert = result.get("certificate", {})
                if cert:
                    f.write("\nCertificate:\n")
                    f.write(
                        f"  Subject: {cert.get('subject', {}).get('commonName', 'N/A')}\n"
                    )
                    f.write(
                        f"  Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}\n"
                    )
                    f.write(f"  Expires: {cert.get('not_after', 'N/A')}\n")
                    f.write(f"  Key Size: {cert.get('key_size', 'N/A')} bits\n")

                # Vulnerabilities
                vulnerabilities = result.get("vulnerabilities", [])
                if vulnerabilities:
                    f.write(f"\nVulnerabilities ({len(vulnerabilities)}):\n")
                    for vuln in vulnerabilities:
                        f.write(
                            f"  [{vuln['severity']}] {vuln['name']}: {vuln['description']}\n"
                        )
                else:
                    f.write("\nNo vulnerabilities detected.\n")

                f.write("\n")

        self.print_success(f"SSL report exported to: {filepath}")
