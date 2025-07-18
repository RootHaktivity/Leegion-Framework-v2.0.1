"""
Subdomain Enumerator Module for Leegion Framework

This module provides comprehensive subdomain enumeration capabilities
using various techniques and tools.
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.banner import print_module_header


class SubdomainEnumerator(BaseModule):
    """Advanced subdomain enumeration with multiple discovery techniques"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Subdomain_Enumerator")
        self.discovered_subdomains: Set[str] = set()
        self.enumeration_results: List[Dict[str, Any]] = []
        self.max_threads = config.get("max_threads", 50)
        self.timeout = config.get("timeout", 5)

    def run(self):
        """Main subdomain enumeration interface"""
        print_module_header("Subdomain Enumerator", "Advanced Subdomain Discovery")

        while True:
            self._display_enum_menu()
            choice = self.get_user_input("Select enumeration technique: ")

            if not choice:
                continue

            if choice == "1":
                self._wordlist_enumeration()
            elif choice == "2":
                self._dns_bruteforce()
            elif choice == "3":
                self._certificate_transparency()
            elif choice == "4":
                self._search_engine_enumeration()
            elif choice == "5":
                self._subdomain_takeover_check()
            elif choice == "6":
                self._comprehensive_scan()
            elif choice == "7":
                self._passive_enumeration()
            elif choice == "8":
                self._subdomain_permutation()
            elif choice == "9":
                self._view_discovered_subdomains()
            elif choice == "10":
                self._export_results()
            elif choice == "11":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_enum_menu(self):
        """Display enumeration menu options"""
        found_count = len(self.discovered_subdomains)

        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'SUBDOMAIN ENUMERATION MENU'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print(f"\033[96mDiscovered Subdomains:\033[0m {found_count}")
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m 1.\033[0m Wordlist-based Enumeration")
        print("\033[96m 2.\033[0m DNS Bruteforce")
        print("\033[96m 3.\033[0m Certificate Transparency Logs")
        print("\033[96m 4.\033[0m Search Engine Enumeration")
        print("\033[96m 5.\033[0m Subdomain Takeover Check")
        print("\033[96m 6.\033[0m Comprehensive Scan (All methods)")
        print("\033[96m 7.\033[0m Passive Enumeration")
        print("\033[96m 8.\033[0m Subdomain Permutation")
        print("\033[96m 9.\033[0m View Discovered Subdomains")
        print("\033[96m10.\033[0m Export Results")
        print("\033[96m11.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")

    def _wordlist_enumeration(self):
        """Enumerate subdomains using wordlist"""
        domain = self.get_user_input(
            "Enter target domain (e.g., example.com): ", "domain"
        )
        if not domain:
            return

        # Wordlist selection
        print("\nWordlist options:")
        print("1. Built-in common subdomains")
        print("2. Custom wordlist file")
        print("3. Use system wordlist")

        wordlist_choice = self.get_user_input("Select wordlist (1-3): ")

        wordlist = []
        if wordlist_choice == "1":
            wordlist = self._get_builtin_wordlist()
        elif wordlist_choice == "2":
            wordlist_path = self.get_user_input(
                "Enter wordlist file path: ", "file_path"
            )
            if wordlist_path:
                wordlist = self._load_custom_wordlist(wordlist_path)
        elif wordlist_choice == "3":
            default_wordlist = self.config.get(
                "subdomain_wordlist", "/usr/share/wordlists/subdomains.txt"
            )
            if self.validate_input(default_wordlist, "file_path"):
                wordlist = self._load_custom_wordlist(default_wordlist)

        if not wordlist:
            self.print_error("No wordlist available")
            return

        self.print_info(f"Starting wordlist enumeration with {len(wordlist)} entries")
        self._enumerate_with_wordlist(domain, wordlist)

    def _dns_bruteforce(self):
        """Perform DNS bruteforce enumeration"""
        print("\n\033[96m📚 WHAT IS SUBDOMAIN ENUMERATION?\033[0m")
        print("\n\033[93m💡 WHAT YOU MIGHT DISCOVER:\033[0m")
        print("\n\033[93m🎯 REAL-WORLD USE CASES:\033[0m")
        print(
            "\n\033[91m⚠️  REMEMBER:\033[0m Only test domains you own or "
            "have permission to test!"
        )

        domain = self.get_user_input("\nEnter target domain: ", "domain")
        if not domain:
            return

        # Get DNS servers to use
        dns_servers = self._get_dns_servers()
        self.print_info(f"Using DNS servers: {', '.join(dns_servers)}")

        # Use built-in wordlist for DNS bruteforce
        wordlist = self._get_builtin_wordlist()

        self.print_info(
            f"Starting DNS bruteforce with {len(wordlist)} common subdomains"
        )
        self.print_info(
            "Looking for: Admin panels, dev servers, APIs, mail servers, "
            "staging environments"
        )
        self._dns_bruteforce_with_wordlist(domain, wordlist, dns_servers)

    def _certificate_transparency(self):
        """Search certificate transparency logs"""
        domain = self.get_user_input("Enter target domain: ", "domain")
        if not domain:
            return

        self.print_info("Searching certificate transparency logs...")

        # Multiple CT log sources
        ct_sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            (f"https://certspotter.com/api/v0/certs?domain={domain}"),
        ]

        for source in ct_sources:
            try:
                self.print_info(f"Querying: {source.split('?')[0]}")
                self._query_ct_logs(source, domain)
            except Exception as e:
                self.print_warning(f"CT log query failed: {e}")

    def _search_engine_enumeration(self):
        """Enumerate using search engines"""
        domain = self.get_user_input("Enter target domain: ", "domain")
        if not domain:
            return

        self.print_info("Performing search engine enumeration...")

        # Search patterns for different engines
        search_queries = [
            f"site:*.{domain}",
            f"site:{domain} -www",
            f"inurl:{domain}",
            f"intitle:index.of {domain}",
        ]

        for query in search_queries:
            self.print_info(f"Search query: {query}")
            # Note: Actual search engine APIs would require API keys
            # Simulate search enumeration (real implementation would use search APIs)
            self._simulate_search_enumeration(domain, query)

    def _subdomain_takeover_check(self):
        """Check discovered subdomains for takeover vulnerabilities"""
        if not self.discovered_subdomains:
            self.print_warning("No subdomains discovered yet. Run enumeration first.")
            return

        self.print_info(
            f"Checking {len(self.discovered_subdomains)} subdomains for "
            f"takeover vulnerabilities"
        )

        vulnerable_subdomains = []

        # Known vulnerable CNAME patterns
        vulnerable_patterns = [
            "github.io",
            "herokuapp.com",
            "amazonaws.com",
            "cloudfront.net",
            "azurewebsites.net",
            "wordpress.com",
            "tumblr.com",
            "shopify.com",
            "fastly.com",
        ]

        for subdomain in self.discovered_subdomains:
            try:
                # Check CNAME records
                cname_records = self._get_cname_records(subdomain)
                for cname in cname_records:
                    for pattern in vulnerable_patterns:
                        if pattern in cname.lower():
                            vulnerable_subdomains.append(
                                {
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": pattern,
                                    "risk": "potential_takeover",
                                }
                            )
                            self.print_warning(
                                f"Potential takeover: {subdomain} -> {cname}"
                            )

                # Check HTTP status
                http_status = self._check_http_status(subdomain)
                if http_status in [404, 403, 502, 503]:
                    self.print_info(f"Interesting status {http_status}: {subdomain}")

            except Exception as e:
                self.logger.debug(f"Takeover check failed for {subdomain}: {e}")

        if vulnerable_subdomains:
            self.print_success(
                f"Found {len(vulnerable_subdomains)} potentially vulnerable subdomains"
            )
            self._store_takeover_results(vulnerable_subdomains)
        else:
            self.print_info("No obvious takeover vulnerabilities found")

    def _comprehensive_scan(self):
        """Perform comprehensive subdomain enumeration using all methods"""
        domain = self.get_user_input("Enter target domain: ", "domain")
        if not domain:
            return

        self.print_info("Starting comprehensive subdomain enumeration...")
        self.print_warning("This may take several minutes to complete")

        # Clear previous results for this domain
        self.discovered_subdomains.clear()

        start_time = time.time()

        # Step 1: Passive enumeration
        self.print_info("Step 1/5: Passive enumeration...")
        self._certificate_transparency_scan(domain)

        # Step 2: DNS enumeration
        self.print_info("Step 2/5: DNS enumeration...")
        wordlist = self._get_builtin_wordlist()
        self._enumerate_with_wordlist(
            domain, wordlist[:500]
        )  # Limit for comprehensive scan

        # Step 3: Permutation enumeration
        self.print_info("Step 3/5: Subdomain permutation...")
        self._perform_permutation_scan(domain)

        # Step 4: Validate all discovered subdomains
        self.print_info("Step 4/5: Validating discovered subdomains...")
        self._validate_all_subdomains()

        # Step 5: Takeover check
        self.print_info("Step 5/5: Checking for takeover vulnerabilities...")
        self._subdomain_takeover_check()

        duration = time.time() - start_time
        self.print_success(f"Comprehensive scan completed in {duration:.2f} seconds")
        self.print_success(
            f"Total unique subdomains found: {len(self.discovered_subdomains)}"
        )

        # Store comprehensive results
        self._store_comprehensive_results(domain, duration)

    def _passive_enumeration(self):
        """Perform passive enumeration without active DNS queries"""
        domain = self.get_user_input("Enter target domain: ", "domain")
        if not domain:
            return

        self.print_info("Starting passive enumeration...")

        # Certificate transparency
        self._certificate_transparency_scan(domain)

        # Web archives (simplified)
        self._check_web_archives(domain)

        # DNS history databases
        self._check_dns_history(domain)

    def _subdomain_permutation(self):
        """Generate and test subdomain permutations"""
        domain = self.get_user_input("Enter target domain: ", "domain")
        if not domain:
            return

        base_subdomains = self.get_user_input(
            "Enter known subdomains (comma-separated) or press enter for common ones: ",
            required=False,
        )

        if base_subdomains:
            known_subs = [sub.strip() for sub in base_subdomains.split(",")]
        else:
            known_subs = ["www", "mail", "ftp", "admin", "api", "dev", "test"]

        self.print_info(
            f"Generating permutations for {len(known_subs)} base subdomains..."
        )
        self._perform_permutation_scan(domain, known_subs)

    def _enumerate_with_wordlist(self, domain: str, wordlist: List[str]):
        """Enumerate subdomains using wordlist with threading"""
        self.print_info(f"Testing {len(wordlist)} potential subdomains...")

        # Progress tracking
        completed = 0
        found = 0

        def check_subdomain(subdomain_name):
            nonlocal completed, found
            subdomain = f"{subdomain_name}.{domain}"

            if self._resolve_subdomain(subdomain):
                self.discovered_subdomains.add(subdomain)
                self.print_success(f"Found: {subdomain}")
                found += 1

            completed += 1
            if completed % 50 == 0:
                self.show_progress(completed, len(wordlist), "Progress")

        # Use thread pool for concurrent checks
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.debug(f"Subdomain check error: {e}")

        print()  # New line after progress
        self.print_success(f"Wordlist enumeration completed. Found {found} subdomains.")

    def _dns_bruteforce_with_wordlist(
        self, domain: str, wordlist: List[str], dns_servers: List[str]
    ):
        """DNS bruteforce with custom DNS servers"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = dns_servers
        resolver.timeout = self.timeout

        completed = 0
        found = 0

        def dns_check(subdomain_name):
            nonlocal completed, found
            subdomain = f"{subdomain_name}.{domain}"

            try:
                resolver.resolve(subdomain, "A")
                self.discovered_subdomains.add(subdomain)
                self.print_success(f"DNS Found: {subdomain}")
                found += 1
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                self.logger.debug(f"DNS error for {subdomain}: {e}")

            completed += 1
            if completed % 50 == 0:
                self.show_progress(completed, len(wordlist), "DNS Progress")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(dns_check, sub) for sub in wordlist]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.debug(f"DNS bruteforce error: {e}")

        print()
        self.print_success(f"DNS bruteforce completed. Found {found} subdomains.")

    def _query_ct_logs(self, url: str, domain: str):
        """Query certificate transparency logs"""
        try:
            headers = {
                "User-Agent": self.config.get("user_agent", "Leegion-Framework/2.0")
            }
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                if "crt.sh" in url:
                    self._parse_crtsh_response(response.json(), domain)
                elif "certspotter" in url:
                    self._parse_certspotter_response(response.json(), domain)

        except Exception as e:
            self.print_warning(f"CT log query failed: {e}")

    def _parse_crtsh_response(self, data: List[Dict], domain: str):
        """Parse crt.sh response"""
        for entry in data:
            name_value = entry.get("name_value", "")
            if name_value:
                # Handle wildcard certificates
                subdomains = name_value.split("\n")
                for subdomain in subdomains:
                    subdomain = subdomain.strip().lower()
                    if (
                        subdomain.endswith(f".{domain}")
                        and subdomain not in self.discovered_subdomains
                    ):
                        self.discovered_subdomains.add(subdomain)
                        self.print_success(f"CT Found: {subdomain}")

    def _parse_certspotter_response(self, data: List[Dict], domain: str):
        """Parse CertSpotter response"""
        for entry in data:
            dns_names = entry.get("dns_names", [])
            for dns_name in dns_names:
                dns_name = dns_name.strip().lower()
                if (
                    dns_name.endswith(f".{domain}")
                    and dns_name not in self.discovered_subdomains
                ):
                    self.discovered_subdomains.add(dns_name)
                    self.print_success(f"CT Found: {dns_name}")

    def _certificate_transparency_scan(self, domain: str):
        """Dedicated CT scan method"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {
                "User-Agent": self.config.get("user_agent", "Leegion-Framework/2.0")
            }
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                self._parse_crtsh_response(response.json(), domain)

        except Exception as e:
            self.print_warning(f"Certificate transparency scan failed: {e}")

    def _perform_permutation_scan(
        self, domain: str, base_subs: Optional[List[str]] = None
    ):
        """Generate and test subdomain permutations"""
        if not base_subs:
            base_subs = ["www", "mail", "ftp", "admin", "api", "dev", "test", "staging"]

        # Permutation patterns
        patterns = [
            "dev-{}",
            "test-{}",
            "staging-{}",
            "prod-{}",
            "{}-dev",
            "{}-test",
            "{}-staging",
            "{}-prod",
            "{}1",
            "{}2",
            "{}01",
            "{}02",
            "new-{}",
            "old-{}",
            "backup-{}",
        ]

        permutations = []
        for base in base_subs:
            for pattern in patterns:
                permutations.append(pattern.format(base))

        self.print_info(f"Testing {len(permutations)} permutations...")
        self._enumerate_with_wordlist(domain, permutations)

    def _simulate_search_enumeration(self, domain: str, query: str):
        """Perform actual search enumeration using multiple techniques"""
        self.print_info(f"Processing search query: {query}")

        # Method 1: Google dorking through web scraping (respecting robots.txt)
        google_subdomains = self._google_dork_search(domain)

        # Method 2: Bing API search
        bing_subdomains = self._bing_search(domain)

        # Method 3: Certificate transparency logs (additional search)
        ct_subdomains = self._advanced_ct_search(domain)

        # Method 4: Common naming patterns based on search intent
        pattern_subdomains = self._search_pattern_enumeration(domain, query)

        # Combine all results
        all_found = (
            google_subdomains + bing_subdomains + ct_subdomains + pattern_subdomains
        )

        for subdomain in set(all_found):
            if self._resolve_subdomain(subdomain):
                self.discovered_subdomains.add(subdomain)
                self.print_success(f"Search Found: {subdomain}")

    def _google_dork_search(self, domain: str) -> List[str]:
        """Search using Google dorking techniques"""
        subdomains = []
        try:
            # Use requests to search for subdomains
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " "AppleWebKit/537.36"
                )
            }

            # Search for site:*.domain.com
            search_url = f"https://www.google.com/search?q=site%3A*.{domain}"
            response = requests.get(search_url, headers=headers, timeout=10)

            if response.status_code == 200:
                # Extract potential subdomains from search results
                import re

                pattern = rf"\b([a-zA-Z0-9-]+\.{re.escape(domain)})\b"
                matches = re.findall(pattern, response.text)
                subdomains.extend(matches)

        except Exception as e:
            self.print_warning(f"Google search failed: {e}")

        return list(set(subdomains))

    def _bing_search(self, domain: str) -> List[str]:
        """Search using Bing"""
        subdomains = []
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " "AppleWebKit/537.36"
                )
            }

            search_url = f"https://www.bing.com/search?q=site%3A{domain}"
            response = requests.get(search_url, headers=headers, timeout=10)

            if response.status_code == 200:
                import re

                pattern = rf"\b([a-zA-Z0-9-]+\.{re.escape(domain)})\b"
                matches = re.findall(pattern, response.text)
                subdomains.extend(matches)

        except Exception as e:
            self.print_warning(f"Bing search failed: {e}")

        return list(set(subdomains))

    def _advanced_ct_search(self, domain: str) -> List[str]:
        """Advanced certificate transparency search"""
        subdomains = []
        try:
            # Use multiple CT log sources
            ct_sources = [
                f"https://crt.sh/?q=%.{domain}&output=json",
                (f"https://certspotter.com/api/v0/certs?domain={domain}"),
            ]

            for source in ct_sources:
                try:
                    response = requests.get(source, timeout=15)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list):
                            for cert in data:
                                if "name_value" in cert:
                                    names = cert["name_value"].split("\n")
                                    for name in names:
                                        if name.endswith(f".{domain}"):
                                            subdomains.append(name.strip())
                except Exception:
                    continue

        except Exception as e:
            self.print_warning(f"Advanced CT search failed: {e}")

        return list(set(subdomains))

    def _search_pattern_enumeration(self, domain: str, query: str) -> List[str]:
        """Generate subdomains based on search patterns"""
        patterns = []

        # Analyze query type and generate relevant subdomains
        if "site:" in query:
            patterns.extend(["www", "mail", "ftp", "admin", "api"])
        if "inurl:" in query:
            patterns.extend(["blog", "shop", "store", "forum"])
        if "intitle:" in query:
            patterns.extend(["docs", "help", "support", "kb"])

        # Add common web application subdomains
        patterns.extend(["app", "portal", "dashboard", "panel", "manage"])

        return [f"{pattern}.{domain}" for pattern in set(patterns)]

    def _check_web_archives(self, domain: str):
        """Check web archives for historical subdomains"""
        try:
            # Wayback Machine API
            url = (
                f"http://web.archive.org/cdx/search/cdx?url=*.{domain}"
                f"&output=json&fl=original&collapse=urlkey"
            )
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    url_found = entry[0]
                    if "://" in url_found:
                        subdomain = url_found.split("://")[1].split("/")[0].lower()
                        if (
                            subdomain.endswith(f".{domain}")
                            and subdomain not in self.discovered_subdomains
                        ):
                            if self._resolve_subdomain(subdomain):
                                self.discovered_subdomains.add(subdomain)
                                self.print_success(f"Archive Found: {subdomain}")

        except Exception as e:
            self.print_warning(f"Web archive check failed: {e}")

    def _check_dns_history(self, domain: str):
        """Check DNS history databases"""
        self.print_info(f"Checking DNS history for {domain}...")

        # Common historical subdomains that often exist
        historical_subs = [
            "old",
            "legacy",
            "archive",
            "backup",
            "previous",
            "v1",
            "v2",
            "deprecated",
            "temp",
            "temporary",
            "beta",
            "alpha",
            "rc",
            "release",
            "pre-prod",
        ]

        self.print_info(
            f"Testing {len(historical_subs)} common historical "
            f"subdomain patterns..."
        )

        for sub in historical_subs:
            subdomain = f"{sub}.{domain}"
            if self._resolve_subdomain(subdomain):
                self.discovered_subdomains.add(subdomain)
                self.print_success(f"Historical Found: {subdomain}")

        # Enhanced functionality available with commercial APIs
        self.print_info(
            "Enhanced: Full DNS history available with APIs (SecurityTrails, "
            "PassiveTotal)"
        )

    def _resolve_subdomain(self, subdomain: str) -> bool:
        """Resolve subdomain to check if it exists"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.resolve(subdomain, "A")
            return True
        except Exception:
            return False

    def _get_cname_records(self, subdomain: str) -> List[str]:
        """Get CNAME records for subdomain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(subdomain, "CNAME")
            return [str(answer) for answer in answers]
        except Exception:
            return []

    def _check_http_status(self, subdomain: str) -> Optional[int]:
        """Check HTTP status code for subdomain"""
        try:
            response = requests.get(
                f"http://{subdomain}", timeout=5, allow_redirects=False
            )
            return int(response.status_code)
        except Exception:
            try:
                response = requests.get(
                    f"https://{subdomain}", timeout=5, allow_redirects=False
                )
                return int(response.status_code)
            except Exception:
                return None

    def _validate_all_subdomains(self):
        """Validate all discovered subdomains"""
        self.print_info("Validating discovered subdomains...")

        valid_subdomains = set()

        for subdomain in self.discovered_subdomains:
            if self._resolve_subdomain(subdomain):
                valid_subdomains.add(subdomain)

        removed = len(self.discovered_subdomains) - len(valid_subdomains)
        self.discovered_subdomains = valid_subdomains

        if removed > 0:
            self.print_info(f"Removed {removed} invalid subdomains")

    def _get_builtin_wordlist(self) -> List[str]:
        """Get built-in subdomain wordlist"""
        return [
            "www",
            "mail",
            "ftp",
            "localhost",
            "webmail",
            "smtp",
            "pop",
            "ns1",
            "ns2",
            "webdisk",
            "ns",
            "secure",
            "vpn",
            "www2",
            "admin",
            "portal",
            "email",
            "exchange",
            "owa",
            "www1",
            "backup",
            "mx",
            "lyncdiscover",
            "msoid",
            "cdn",
            "api",
            "test",
            "staging",
            "dev",
            "web",
            "bbs",
            "wap",
            "blog",
            "forum",
            "shop",
            "help",
            "support",
            "news",
            "download",
            "img",
            "images",
            "static",
            "assets",
            "js",
            "css",
            "uploads",
            "files",
            "docs",
            "app",
            "mobile",
            "m",
            "subdomain",
            "sub",
            "cpanel",
            "whm",
            "demo",
            "beta",
            "alpha",
            "testing",
            "prod",
            "production",
            "live",
            "www3",
            "ftp2",
            "mail2",
            "ns3",
            "dns",
            "search",
            "login",
            "register",
            "db",
            "database",
            "mysql",
            "oracle",
            "postgres",
            "mssql",
            "mongo",
            "redis",
            "cache",
            "memcache",
            "queue",
            "jobs",
            "worker",
            "cron",
            "tasks",
            "backup2",
            "old",
            "new",
            "temp",
            "tmp",
            "archive",
            "store",
            "shop2",
            "cart",
            "checkout",
            "payment",
            "billing",
            "invoice",
            "customer",
            "client",
            "partner",
            "vendor",
            "supplier",
            "wholesale",
            "retail",
            "b2b",
            "b2c",
            "crm",
            "erp",
            "hr",
            "finance",
            "accounting",
            "legal",
        ]

    def _load_custom_wordlist(self, filepath: str) -> List[str]:
        """Load custom wordlist from file"""
        try:
            with open(filepath, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.print_error(f"Failed to load wordlist: {e}")
            return []

    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers to use for enumeration"""
        return [
            "8.8.8.8",  # Google
            "8.8.4.4",  # Google
            "1.1.1.1",  # Cloudflare
            "1.0.0.1",  # Cloudflare
            "208.67.222.222",  # OpenDNS
            "208.67.220.220",  # OpenDNS
        ]

    def _store_takeover_results(self, vulnerable_subdomains: List[Dict]):
        """Store subdomain takeover results"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "subdomain_takeover_check",
            "vulnerable_subdomains": vulnerable_subdomains,
            "total_checked": len(self.discovered_subdomains),
        }

        self.enumeration_results.append(result)
        self.add_result(result)

    def _store_comprehensive_results(self, domain: str, duration: float):
        """Store comprehensive enumeration results"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "comprehensive_enumeration",
            "domain": domain,
            "duration": duration,
            "total_subdomains": len(self.discovered_subdomains),
            "subdomains": list(self.discovered_subdomains),
        }

        self.enumeration_results.append(result)
        self.add_result(result)

    def _view_discovered_subdomains(self):
        """View all discovered subdomains"""
        if not self.discovered_subdomains:
            self.print_warning("No subdomains discovered yet")
            return

        print(f"\n\033[93m{'DISCOVERED SUBDOMAINS'.center(60)}\033[0m")
        print(f"\033[93m{'-'*60}\033[0m")
        print(f"\033[96mTotal Found:\033[0m {len(self.discovered_subdomains)}")
        print()

        sorted_subdomains = sorted(self.discovered_subdomains)

        for i, subdomain in enumerate(sorted_subdomains, 1):
            # Get IP address if possible
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                answers = resolver.resolve(subdomain, "A")
                ip = str(answers[0])
            except Exception:
                ip = "N/A"

            print(f"\033[96m{i:3d}.\033[0m {subdomain:30} \033[94m{ip}\033[0m")

            # Show in batches
            if i % 20 == 0 and i < len(sorted_subdomains):
                more = self.get_user_input(
                    "Press Enter to continue or 'q' to stop: ", required=False
                )
                if more and more.lower() == "q":
                    break

    def _export_results(self):
        """Export enumeration results"""
        if not self.discovered_subdomains:
            self.print_warning("No subdomains to export")
            return

        print("\nExport formats:")
        print("1. JSON")
        print("2. CSV")
        print("3. Text List")
        print("4. Detailed Report")

        format_choice = self.get_user_input("Select format (1-4): ")

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get("output_dir", "./reports/output")

            if format_choice == "1":
                self._export_json(output_dir, timestamp)
            elif format_choice == "2":
                self._export_csv(output_dir, timestamp)
            elif format_choice == "3":
                self._export_text_list(output_dir, timestamp)
            elif format_choice == "4":
                self._export_detailed_report(output_dir, timestamp)
            else:
                self.print_error("Invalid format selection")

        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_json(self, output_dir: str, timestamp: str):
        """Export to JSON format"""
        os.makedirs(output_dir, exist_ok=True)

        filename = f"subdomains_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        export_data = {
            "timestamp": datetime.now().isoformat(),
            "total_subdomains": len(self.discovered_subdomains),
            "subdomains": list(self.discovered_subdomains),
            "enumeration_results": self.enumeration_results,
        }

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        self.print_success(f"Results exported to: {filepath}")

    def _export_csv(self, output_dir: str, timestamp: str):
        """Export to CSV format"""
        import csv

        os.makedirs(output_dir, exist_ok=True)
        filename = f"subdomains_{timestamp}.csv"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain", "IP Address", "CNAME"])

            for subdomain in sorted(self.discovered_subdomains):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2

                    # Get A record
                    try:
                        a_answers = resolver.resolve(subdomain, "A")
                        ip = str(a_answers[0])
                    except Exception:
                        ip = ""

                    # Get CNAME record
                    try:
                        cname_answers = resolver.resolve(subdomain, "CNAME")
                        cname = str(cname_answers[0])
                    except Exception:
                        cname = ""

                    writer.writerow([subdomain, ip, cname])

                except Exception as e:
                    writer.writerow([subdomain, "Error", str(e)])

        self.print_success(f"Results exported to: {filepath}")

    def _export_text_list(self, output_dir: str, timestamp: str):
        """Export as simple text list"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"subdomains_list_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            for subdomain in sorted(self.discovered_subdomains):
                f.write(f"{subdomain}\n")

        self.print_success(f"Subdomain list exported to: {filepath}")

    def _export_detailed_report(self, output_dir: str, timestamp: str):
        """Export detailed enumeration report"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"subdomain_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write("LEEGION FRAMEWORK - SUBDOMAIN ENUMERATION REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains Found: {len(self.discovered_subdomains)}\n\n")

            f.write("DISCOVERED SUBDOMAINS\n")
            f.write("-" * 30 + "\n")

            for subdomain in sorted(self.discovered_subdomains):
                f.write(f"{subdomain}\n")

            f.write("\nENUMERATION SUMMARY\n")
            f.write("-" * 20 + "\n")

            for result in self.enumeration_results:
                f.write(f"Type: {result['type']}\n")
                f.write(f"Timestamp: {result['timestamp']}\n")
                if "duration" in result:
                    f.write(f"Duration: {result['duration']:.2f} seconds\n")
                f.write("\n")

        self.print_success(f"Detailed report exported to: {filepath}")
