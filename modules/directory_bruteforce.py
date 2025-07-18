"""
Directory Bruteforce Module for Leegion Framework

This module provides directory and file enumeration capabilities
using various bruteforce techniques.
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import requests
import csv
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from core.base_module import BaseModule
from core.banner import print_module_header
from core.security import network_rate_limiter


class DirectoryBruteforcer(BaseModule):
    """Advanced directory and file bruteforce with intelligent scanning"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Directory_Bruteforcer")
        self.discovered_paths: Set[str] = set()
        self.scan_results: List[Dict[str, Any]] = []
        self.max_threads = config.get("max_threads", 20)
        self.timeout = config.get("timeout", 10)
        self.user_agent = config.get("user_agent", "Leegion-Framework/2.0")

        # Response analysis
        self.baseline_responses: Dict[str, List[Dict[str, Any]]] = {}
        self.interesting_status_codes = [200, 301, 302, 401, 403, 500, 501, 502, 503]

    def run(self):
        """Main directory bruteforce interface"""
        print_module_header("Directory Bruteforcer", "Web Directory & File Discovery")

        while True:
            self._display_bruteforce_menu()
            choice = self.get_user_input("Select scanning option: ")

            if not choice:
                continue

            if choice == "1":
                self._quick_directory_scan()
            elif choice == "2":
                self._comprehensive_scan()
            elif choice == "3":
                self._custom_wordlist_scan()
            elif choice == "4":
                self._file_extension_scan()
            elif choice == "5":
                self._backup_file_scan()
            elif choice == "6":
                self._common_files_scan()
            elif choice == "7":
                self._recursive_scan()
            elif choice == "8":
                self._technology_specific_scan()
            elif choice == "9":
                self._view_discovered_paths()
            elif choice == "10":
                self._export_results()
            elif choice == "11":
                break
            else:
                self.print_error("Invalid selection. Please try again.")

    def _display_bruteforce_menu(self):
        """Display directory bruteforce menu"""
        found_count = len(self.discovered_paths)

        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'DIRECTORY BRUTEFORCE MENU'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print(f"\033[96mDiscovered Paths:\033[0m {found_count}")
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m 1.\033[0m Quick Directory Scan")
        print("\033[96m 2.\033[0m Comprehensive Scan")
        print("\033[96m 3.\033[0m Custom Wordlist Scan")
        print("\033[96m 4.\033[0m File Extension Scan")
        print("\033[96m 5.\033[0m Backup File Discovery")
        print("\033[96m 6.\033[0m Common Files Scan")
        print("\033[96m 7.\033[0m Recursive Directory Scan")
        print("\033[96m 8.\033[0m Technology-Specific Scan")
        print("\033[96m 9.\033[0m View Discovered Paths")
        print("\033[96m10.\033[0m Export Results")
        print("\033[96m11.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")

    def _quick_directory_scan(self):
        """Perform quick directory scan with common directories"""
        print("\n\033[96m📚 WHAT IS DIRECTORY BRUTEFORCING?\033[0m")
        print("\n\033[93m💡 WHAT YOU MIGHT FIND:\033[0m")
        print("• /admin/ - Administrative panels and login pages")
        print("• /backup/ - Database backups and sensitive files")
        print("• /.git/ - Source code repositories accidentally exposed")
        print("• /api/ - API endpoints for data access")
        print("• /config/ - Configuration files with passwords")
        print(
            "\n\033[91m⚠️  REMEMBER:\033[0m Only test sites you own or "
            "have permission to test!"
        )

        target_url = self.get_user_input(
            "\nEnter target URL (e.g., https://example.com): ", "url"
        )
        if not target_url:
            return

        # Ensure URL format
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        # Test base URL first
        if not self._test_base_url(target_url):
            return

        # Quick wordlist with real-world examples
        quick_wordlist = [
            "admin",
            "administrator",
            "login",
            "dashboard",
            "panel",
            "cp",
            "controlpanel",
            "api",
            "v1",
            "v2",
            "docs",
            "documentation",
            "help",
            "support",
            "uploads",
            "files",
            "assets",
            "static",
            "images",
            "img",
            "css",
            "js",
            "backup",
            "backups",
            "bak",
            "old",
            "new",
            "temp",
            "tmp",
            "test",
            "testing",
            "dev",
            "development",
            "staging",
            "prod",
            "production",
            "config",
            "configuration",
            "settings",
            "setup",
            "install",
            "installation",
        ]

        self.print_info(f"Testing {len(quick_wordlist)} common directories...")
        self.print_info("Looking for: Admin panels, backups, APIs, configuration files")
        self._perform_directory_scan(target_url, quick_wordlist, "Quick Directory Scan")

    def _comprehensive_scan(self):
        """Perform comprehensive directory and file scan"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        if not self._test_base_url(target_url):
            return

        self.print_warning(
            "Comprehensive scan may take significant time and generate many requests!"
        )
        confirm = self.get_user_input("Continue? (y/N): ")
        if confirm and confirm.lower() != "y":
            return

        # Large comprehensive wordlist
        comprehensive_wordlist = self._get_comprehensive_wordlist()

        self.print_info(
            f"Starting comprehensive scan with {len(comprehensive_wordlist)} paths..."
        )
        self._perform_directory_scan(
            target_url, comprehensive_wordlist, "Comprehensive Scan"
        )

    def _custom_wordlist_scan(self):
        """Scan using custom wordlist file"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        wordlist_path = self.get_user_input("Enter wordlist file path: ", "file_path")
        if not wordlist_path:
            return

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        if not self._test_base_url(target_url):
            return

        # Load custom wordlist
        wordlist = self._load_wordlist_file(wordlist_path)
        if not wordlist:
            return

        self.print_info(
            f"Starting custom wordlist scan with {len(wordlist)} entries..."
        )
        self._perform_directory_scan(target_url, wordlist, "Custom Wordlist Scan")

    def _file_extension_scan(self):
        """Scan for files with specific extensions"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        print("\nFile extension options:")
        print("1. Common web files (.php, .asp, .jsp, .html)")
        print("2. Configuration files (.conf, .config, .ini, .xml)")
        print("3. Backup files (.bak, .backup, .old, .save)")
        print("4. Database files (.sql, .db, .sqlite)")
        print("5. Archive files (.zip, .tar, .gz, .rar)")
        print("6. Custom extensions")

        ext_choice = self.get_user_input("Select extension category (1-6): ")

        extensions = []
        if ext_choice == "1":
            extensions = ["php", "asp", "aspx", "jsp", "html", "htm", "js", "css"]
        elif ext_choice == "2":
            extensions = ["conf", "config", "ini", "xml", "json", "yaml", "yml"]
        elif ext_choice == "3":
            extensions = ["bak", "backup", "old", "save", "orig", "copy"]
        elif ext_choice == "4":
            extensions = ["sql", "db", "sqlite", "sqlite3", "mdb"]
        elif ext_choice == "5":
            extensions = ["zip", "tar", "gz", "rar", "7z", "tar.gz"]
        elif ext_choice == "6":
            custom_exts = self.get_user_input("Enter extensions (comma-separated): ")
            if custom_exts:
                extensions = [ext.strip() for ext in custom_exts.split(",")]

        if not extensions:
            self.print_error("No extensions specified")
            return

        # Generate file list with extensions
        base_names = [
            "index",
            "default",
            "main",
            "home",
            "admin",
            "login",
            "config",
            "settings",
        ]
        file_list = []

        for name in base_names:
            for ext in extensions:
                file_list.append(f"{name}.{ext}")

        self.print_info(
            f"Scanning for {len(file_list)} files with selected extensions..."
        )
        self._perform_directory_scan(target_url, file_list, "File Extension Scan")

    def _backup_file_scan(self):
        """Scan for common backup files"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        # Common backup file patterns
        backup_patterns = [
            "backup.zip",
            "backup.tar.gz",
            "backup.sql",
            "database.sql",
            "db.sql",
            "site.zip",
            "website.zip",
            "web.tar.gz",
            "www.zip",
            "config.bak",
            "settings.bak",
            "database.bak",
            "index.php.bak",
            "index.html.bak",
            "admin.php.bak",
            ".env",
            ".env.bak",
            ".env.old",
            ".env.backup",
            "wp-config.php.bak",
            "config.php.bak",
            "settings.php.bak",
            "robots.txt.bak",
            ".htaccess.bak",
            "web.config.bak",
        ]

        self.print_info(f"Scanning for {len(backup_patterns)} backup files...")
        self._perform_directory_scan(target_url, backup_patterns, "Backup File Scan")

    def _common_files_scan(self):
        """Scan for common web files and configurations"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        common_files = [
            "robots.txt",
            "sitemap.xml",
            "humans.txt",
            "security.txt",
            ".htaccess",
            ".htpasswd",
            "web.config",
            ".env",
            "readme.txt",
            "README.md",
            "changelog.txt",
            "CHANGELOG.md",
            "license.txt",
            "LICENSE",
            "version.txt",
            "VERSION",
            "crossdomain.xml",
            "clientaccesspolicy.xml",
            "favicon.ico",
            "apple-touch-icon.png",
            "phpinfo.php",
            "info.php",
            "test.php",
            "server-status",
            "server-info",
            "status",
        ]

        self.print_info(f"Scanning for {len(common_files)} common files...")
        self._perform_directory_scan(target_url, common_files, "Common Files Scan")

    def _recursive_scan(self):
        """Perform recursive directory scanning"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        max_depth = (
            self.get_user_input("Enter maximum recursion depth (default: 2): ") or "2"
        )
        try:
            max_depth = int(max_depth)
        except ValueError:
            max_depth = 2

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        if not self._test_base_url(target_url):
            return

        self.print_info(f"Starting recursive scan with max depth: {max_depth}")
        self._perform_recursive_scan(target_url, max_depth)

    def _technology_specific_scan(self):
        """Scan for technology-specific files and directories"""
        target_url = self.get_user_input("Enter target URL: ", "url")
        if not target_url:
            return

        print("\nTechnology-specific scans:")
        print("1. WordPress")
        print("2. Drupal")
        print("3. Joomla")
        print("4. PHP Applications")
        print("5. ASP.NET Applications")
        print("6. Node.js Applications")
        print("7. Python Applications")

        tech_choice = self.get_user_input("Select technology (1-7): ")

        wordlists = {
            "1": self._get_wordpress_wordlist(),
            "2": self._get_drupal_wordlist(),
            "3": self._get_joomla_wordlist(),
            "4": self._get_php_wordlist(),
            "5": self._get_aspnet_wordlist(),
            "6": self._get_nodejs_wordlist(),
            "7": self._get_python_wordlist(),
        }

        if tech_choice not in wordlists:
            self.print_error("Invalid technology selection")
            return

        wordlist = wordlists[tech_choice]
        tech_names = [
            "WordPress",
            "Drupal",
            "Joomla",
            "PHP",
            "ASP.NET",
            "Node.js",
            "Python",
        ]
        tech_name = tech_names[int(tech_choice) - 1]

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        self.print_info(
            f"Starting {tech_name} specific scan with {len(wordlist)} paths..."
        )
        self._perform_directory_scan(target_url, wordlist, f"{tech_name} Specific Scan")

    def _perform_directory_scan(
        self, base_url: str, wordlist: List[str], scan_type: str
    ):
        """Perform directory scan with threading"""
        if not self._establish_baseline(base_url):
            self.print_error("Failed to establish baseline responses")
            return

        self.print_info(f"Starting {scan_type}...")
        start_time = time.time()

        # Progress tracking
        completed = 0
        found = 0

        def scan_path(path):
            nonlocal completed, found

            url = urljoin(base_url, path)
            result = self._test_url(url)

            if result and self._is_interesting_response(result):
                self.discovered_paths.add(url)
                status_color = self._get_status_color(result["status_code"])
                self.print_success(
                    f"Found [{status_color}{result['status_code']}\033[0m] "
                    f"{url} ({result['size']} bytes)"
                )
                found += 1

            completed += 1
            if completed % 20 == 0:
                self.show_progress(completed, len(wordlist), "Scanning")

        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(scan_path, path) for path in wordlist]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.debug(f"Scan error: {e}")

        print()  # New line after progress
        scan_duration = time.time() - start_time

        self.print_success(f"{scan_type} completed in {scan_duration:.2f} seconds")
        self.print_success(f"Found {found} interesting paths")

        # Store scan results
        self._store_scan_results(base_url, scan_type, scan_duration, found, wordlist)

    def _perform_recursive_scan(
        self, base_url: str, max_depth: int, current_depth: int = 0
    ):
        """Perform recursive directory scanning"""
        if current_depth >= max_depth:
            return

        # Get directories found at current level
        current_dirs = [
            url
            for url in self.discovered_paths
            if url.count("/") == base_url.count("/") + current_depth
        ]

        if not current_dirs and current_depth == 0:
            # First run - scan base level
            wordlist = [
                "admin",
                "api",
                "app",
                "assets",
                "backup",
                "config",
                "data",
                "files",
                "images",
                "uploads",
            ]
            self._perform_directory_scan(
                base_url, wordlist, f"Recursive Scan Level {current_depth}"
            )

        # Scan each discovered directory
        for dir_url in current_dirs:
            if not dir_url.endswith("/"):
                dir_url += "/"

            wordlist = ["admin", "config", "backup", "files", "data", "logs", "temp"]
            self.print_info(f"Recursively scanning: {dir_url}")
            self._perform_directory_scan(
                dir_url, wordlist, f"Recursive Scan Level {current_depth + 1}"
            )

        # Recurse to next level
        if current_depth < max_depth - 1:
            self._perform_recursive_scan(base_url, max_depth, current_depth + 1)

    def _test_base_url(self, url: str) -> bool:
        """Test if base URL is accessible"""
        try:
            response = requests.get(
                url, timeout=self.timeout, headers={"User-Agent": self.user_agent}
            )
            if response.status_code == 200:
                self.print_success(f"Base URL accessible: {url}")
                return True
            else:
                self.print_warning(
                    f"Base URL returned status {response.status_code}: {url}"
                )
                return True  # Continue anyway
        except Exception as e:
            self.print_error(f"Cannot access base URL {url}: {e}")
            return False

    def _establish_baseline(self, base_url: str) -> bool:
        """Establish baseline responses for 404 and other error pages"""
        try:
            # Test non-existent paths to establish 404 baseline
            random_paths = [
                f"nonexistent_{random.randint(1000, 9999)}.html",
                f"notfound_{random.randint(1000, 9999)}.php",
                f"missing_{random.randint(1000, 9999)}.asp",
            ]

            self.baseline_responses = {
                "404_responses": [],
                "403_responses": [],
                "error_responses": [],
            }

            for path in random_paths:
                url = urljoin(base_url, path)
                result = self._test_url(url)
                if result:
                    if result["status_code"] == 404:
                        self.baseline_responses["404_responses"].append(result)
                    elif result["status_code"] == 403:
                        self.baseline_responses["403_responses"].append(result)
                    else:
                        self.baseline_responses["error_responses"].append(result)

            self.print_info("Baseline responses established")
            return True

        except Exception as e:
            self.print_error(f"Failed to establish baseline: {e}")
            return False

    def _test_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Test a single URL and return response information"""
        try:
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            # Rate limiting for network requests
            while not network_rate_limiter.allow():
                time.sleep(0.05)
            response = requests.get(
                url,
                timeout=self.timeout,
                headers=headers,
                allow_redirects=True,
                verify=False,  # Ignore SSL warnings
            )

            return {
                "url": url,
                "status_code": response.status_code,
                "size": len(response.content),
                "headers": dict(response.headers),
                "content_type": response.headers.get("content-type", ""),
                "response_time": response.elapsed.total_seconds(),
            }

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception as e:
            self.logger.debug(f"URL test error for {url}: {e}")
            return None

    def _is_interesting_response(self, result: Dict[str, Any]) -> bool:
        """Determine if a response is interesting based on status code and content"""
        status_code = result["status_code"]

        # Always interesting status codes
        if status_code in [200, 301, 302, 401, 403, 500, 501, 502, 503]:
            # Additional filtering for common false positives
            if status_code == 404:
                return False

            # Check if response is different from baseline 404s
            if status_code == 200:
                return self._is_different_from_baseline(result)

            return True

        return False

    def _is_different_from_baseline(self, result: Dict[str, Any]) -> bool:
        """Check if response is significantly different from baseline 404 responses"""
        if not self.baseline_responses.get("404_responses"):
            return True

        # Compare size
        baseline_sizes = [r["size"] for r in self.baseline_responses["404_responses"]]
        avg_baseline_size = sum(baseline_sizes) / len(baseline_sizes)

        # If response size is significantly different, it's likely interesting
        size_difference = abs(result["size"] - avg_baseline_size)
        if size_difference > 100:  # At least 100 bytes difference
            return True

        # Compare content type
        baseline_content_types = [
            r["content_type"] for r in self.baseline_responses["404_responses"]
        ]
        if result["content_type"] not in baseline_content_types:
            return True

        return False

    def _get_status_color(self, status_code: int) -> str:
        """Get color code for status code"""
        if status_code == 200:
            return "\033[92m"  # Green
        elif status_code in [301, 302]:
            return "\033[93m"  # Yellow
        elif status_code in [401, 403]:
            return "\033[94m"  # Blue
        elif status_code >= 500:
            return "\033[91m"  # Red
        else:
            return "\033[95m"  # Magenta

    def _load_wordlist_file(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(filepath, "r") as f:
                wordlist = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            self.print_success(f"Loaded {len(wordlist)} entries from wordlist")
            return wordlist
        except Exception as e:
            self.print_error(f"Failed to load wordlist: {e}")
            return []

    def _get_comprehensive_wordlist(self) -> List[str]:
        """Get comprehensive directory/file wordlist"""
        return [
            # Common directories
            "admin",
            "administrator",
            "administration",
            "panel",
            "cp",
            "controlpanel",
            "dashboard",
            "manage",
            "management",
            "manager",
            "login",
            "signin",
            "auth",
            "api",
            "v1",
            "v2",
            "v3",
            "rest",
            "graphql",
            "webhook",
            "endpoints",
            "docs",
            "documentation",
            "help",
            "support",
            "manual",
            "guide",
            "uploads",
            "files",
            "file",
            "download",
            "downloads",
            "data",
            "assets",
            "static",
            "public",
            "resources",
            "media",
            "images",
            "img",
            "pics",
            "css",
            "js",
            "javascript",
            "styles",
            "scripts",
            "lib",
            "libraries",
            "backup",
            "backups",
            "bak",
            "old",
            "archive",
            "archives",
            "temp",
            "tmp",
            "test",
            "testing",
            "tests",
            "dev",
            "development",
            "staging",
            "prod",
            "production",
            "live",
            "www",
            "web",
            "site",
            "app",
            "application",
            "config",
            "configuration",
            "settings",
            "setup",
            "install",
            "installation",
            "cache",
            "logs",
            "log",
            "debug",
            "error",
            "errors",
            "reports",
            "report",
            # Common files
            "index.html",
            "index.php",
            "index.asp",
            "index.aspx",
            "index.jsp",
            "default.html",
            "default.php",
            "default.asp",
            "default.aspx",
            "home.html",
            "home.php",
            "main.html",
            "main.php",
            "robots.txt",
            "sitemap.xml",
            "humans.txt",
            "security.txt",
            ".htaccess",
            ".htpasswd",
            "web.config",
            ".env",
            "config.php",
            "readme.txt",
            "README.md",
            "changelog.txt",
            "license.txt",
            "phpinfo.php",
            "info.php",
            "test.php",
            "server.php",
            "wp-config.php",
            "wp-admin",
            "wp-content",
            "wp-includes",
            # Technology specific
            "cgi-bin",
            "scripts",
            "servlet",
            "WEB-INF",
            "META-INF",
            "node_modules",
            "vendor",
            "composer.json",
            "package.json",
            ".git",
            ".svn",
            ".hg",
            ".bzr",
            "CVS",
            # Security related
            "secure",
            "security",
            "private",
            "restricted",
            "confidential",
            "internal",
            "intranet",
            "vpn",
            "ssl",
            "tls",
            "certificate",
            # Common subdirectories
            "blog",
            "news",
            "forum",
            "shop",
            "store",
            "cart",
            "checkout",
            "search",
            "contact",
            "about",
            "services",
            "products",
            "portfolio",
        ]

    def _get_wordpress_wordlist(self) -> List[str]:
        """Get WordPress-specific wordlist"""
        return [
            "wp-admin",
            "wp-content",
            "wp-includes",
            "wp-config.php",
            "wp-content/uploads",
            "wp-content/themes",
            "wp-content/plugins",
            "wp-content/cache",
            "wp-content/backup",
            "wp-content/backups",
            "wp-admin/admin.php",
            "wp-admin/admin-ajax.php",
            "wp-login.php",
            "xmlrpc.php",
            "wp-cron.php",
            "wp-mail.php",
            "wp-settings.php",
            "wp-blog-header.php",
            "wp-load.php",
            "wp-trackback.php",
            "readme.html",
            "license.txt",
            "wp-config-sample.php",
        ]

    def _get_drupal_wordlist(self) -> List[str]:
        """Get Drupal-specific wordlist"""
        return [
            "user",
            "admin",
            "node",
            "sites",
            "modules",
            "themes",
            "includes",
            "misc",
            "profiles",
            "scripts",
            "update.php",
            "install.php",
            "cron.php",
            "xmlrpc.php",
            "authorize.php",
            "CHANGELOG.txt",
            "COPYRIGHT.txt",
            "INSTALL.txt",
            "LICENSE.txt",
            "MAINTAINERS.txt",
            "README.txt",
            "UPGRADE.txt",
        ]

    def _get_joomla_wordlist(self) -> List[str]:
        """Get Joomla-specific wordlist"""
        return [
            "administrator",
            "components",
            "modules",
            "plugins",
            "templates",
            "libraries",
            "media",
            "cache",
            "logs",
            "tmp",
            "language",
            "configuration.php",
            "htaccess.txt",
            "web.config.txt",
            "README.txt",
            "LICENSE.txt",
            "CONTRIBUTING.md",
        ]

    def _get_php_wordlist(self) -> List[str]:
        """Get PHP application wordlist"""
        return [
            "config.php",
            "settings.php",
            "database.php",
            "db.php",
            "connect.php",
            "connection.php",
            "constants.php",
            "defines.php",
            "functions.php",
            "common.php",
            "init.php",
            "bootstrap.php",
            "autoload.php",
            "composer.json",
            "composer.lock",
            "phpinfo.php",
            "info.php",
            "test.php",
            "debug.php",
        ]

    def _get_aspnet_wordlist(self) -> List[str]:
        """Get ASP.NET application wordlist"""
        return [
            "web.config",
            "global.asax",
            "default.aspx",
            "default.asp",
            "bin",
            "App_Code",
            "App_Data",
            "App_GlobalResources",
            "App_LocalResources",
            "App_Themes",
            "App_WebReferences",
            "aspnet_client",
            "WebResource.axd",
            "ScriptResource.axd",
        ]

    def _get_nodejs_wordlist(self) -> List[str]:
        """Get Node.js application wordlist"""
        return [
            "package.json",
            "package-lock.json",
            "node_modules",
            "app.js",
            "server.js",
            "index.js",
            "main.js",
            "config",
            "routes",
            "models",
            "views",
            "controllers",
            "public",
            "static",
            "assets",
            "uploads",
            "dist",
            "build",
        ]

    def _get_python_wordlist(self) -> List[str]:
        """Get Python application wordlist"""
        return [
            "requirements.txt",
            "setup.py",
            "app.py",
            "main.py",
            "manage.py",
            "wsgi.py",
            "settings.py",
            "config.py",
            "static",
            "templates",
            "media",
            "uploads",
            "venv",
            "env",
            ".env",
            "virtualenv",
        ]

    def _store_scan_results(
        self,
        target_url: str,
        scan_type: str,
        duration: float,
        found_count: int,
        wordlist: List[str],
    ):
        """Store scan results"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "scan_type": scan_type,
            "duration": duration,
            "wordlist_size": len(wordlist),
            "paths_found": found_count,
            "discovered_paths": list(self.discovered_paths),
        }

        self.scan_results.append(result)
        self.add_result(result)

    def _view_discovered_paths(self):
        """View all discovered paths"""
        if not self.discovered_paths:
            self.print_warning("No paths discovered yet")
            return

        print(f"\n\033[93m{'DISCOVERED PATHS'.center(80)}\033[0m")
        print(f"\033[93m{'-'*80}\033[0m")
        print(f"\033[96mTotal Found:\033[0m {len(self.discovered_paths)}")
        print()

        sorted_paths = sorted(self.discovered_paths)

        for i, path in enumerate(sorted_paths, 1):
            # Test current status
            result = self._test_url(path)
            if result:
                status_color = self._get_status_color(result["status_code"])
                print(
                    f"\033[96m{i:3d}.\033[0m [{status_color}{result['status_code']}\033[0m] "
                    f"{path}"
                )
            else:
                print(f"\033[96m{i:3d}.\033[0m [   ] {path}")

            # Show in batches
            if i % 15 == 0 and i < len(sorted_paths):
                more = self.get_user_input("Press Enter to continue or 'q' to stop: ")
                if more and more.lower() == "q":
                    break

    def _export_results(self):
        """Export discovered paths and scan results"""
        if not self.discovered_paths:
            self.print_warning("No paths to export")
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

        filename = f"directory_scan_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        export_data = {
            "timestamp": datetime.now().isoformat(),
            "total_paths": len(self.discovered_paths),
            "discovered_paths": list(self.discovered_paths),
            "scan_results": self.scan_results,
        }

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        self.print_success(f"Results exported to: {filepath}")

    def _export_csv(self, output_dir: str, timestamp: str):
        """Export to CSV format"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"directory_scan_{timestamp}.csv"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Status Code", "Content Size", "Content Type"])

            for path in sorted(self.discovered_paths):
                result = self._test_url(path)
                if result:
                    writer.writerow(
                        [
                            path,
                            result["status_code"],
                            result["size"],
                            result["content_type"],
                        ]
                    )
                else:
                    writer.writerow([path, "N/A", "N/A", "N/A"])

        self.print_success(f"Results exported to: {filepath}")

    def _export_text_list(self, output_dir: str, timestamp: str):
        """Export as simple text list"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"directory_list_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            for path in sorted(self.discovered_paths):
                f.write(f"{path}\n")

        self.print_success(f"Path list exported to: {filepath}")

    def _export_detailed_report(self, output_dir: str, timestamp: str):
        """Export detailed scan report"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"directory_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write("LEEGION FRAMEWORK - DIRECTORY BRUTEFORCE REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Paths Found: {len(self.discovered_paths)}\n\n")

            f.write("DISCOVERED PATHS\n")
            f.write("-" * 20 + "\n")

            for path in sorted(self.discovered_paths):
                result = self._test_url(path)
                if result:
                    f.write(
                        f"[{result['status_code']}] {path} ({result['size']} bytes)\n"
                    )
                else:
                    f.write(f"[N/A] {path}\n")

            f.write("\nSCAN SUMMARY\n")
            f.write("-" * 15 + "\n")

            for scan in self.scan_results:
                f.write(f"Scan Type: {scan['scan_type']}\n")
                f.write(f"Target: {scan['target_url']}\n")
                f.write(f"Duration: {scan['duration']:.2f} seconds\n")
                f.write(f"Paths Found: {scan['paths_found']}\n")
                f.write(f"Wordlist Size: {scan['wordlist_size']}\n\n")

        self.print_success(f"Detailed report exported to: {filepath}")
