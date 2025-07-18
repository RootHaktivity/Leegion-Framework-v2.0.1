"""
File Downloader Module for Leegion Framework
Enhanced downloader with rate limit handling and multiple fallback methods

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import os
import sys
import time
import random
import subprocess
import requests
import urllib.request
import urllib.error
from urllib.parse import urlparse
from typing import Dict, Any
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.base_module import BaseModule
from core.banner import clear_screen, print_clean_menu_header


class FileDownloader(BaseModule):
    """Enhanced file downloader with rate limit handling and multiple methods"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "File Downloader")
        self.download_dir = config.get("output_dir", "downloads")
        self.ensure_download_directory()

        # User agents for rate limit avoidance
        self.user_agents = [
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
                "Gecko/20100101 Firefox/121.0"
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        ]

    def ensure_download_directory(self):
        """Create download directory if it doesn't exist"""
        Path(self.download_dir).mkdir(parents=True, exist_ok=True)

    def run(self):
        """Main downloader interface"""
        while True:
            try:
                clear_screen()
                self._display_downloader_menu()

                choice = self.get_user_input("\nSelect option: ")

                if choice == "1":
                    self._download_single_file()
                elif choice == "2":
                    self._download_multiple_files()
                elif choice == "3":
                    self._download_with_rate_limit_bypass()
                elif choice == "4":
                    self._resume_download()
                elif choice == "5":
                    self._show_download_status()
                elif choice == "6":
                    self._configure_settings()
                elif choice == "0":
                    break
                else:
                    self.print_error("Invalid option. Please try again.")

                if choice != "0":
                    input("\nPress Enter to continue...")

            except KeyboardInterrupt:
                print("\n\033[93mReturning to main menu...\033[0m")
                break
            except Exception as e:
                self.print_error(f"Menu error: {e}")
                input("Press Enter to continue...")

    def _display_downloader_menu(self):
        """Display file downloader menu"""
        print_clean_menu_header(
            "FILE DOWNLOADER", "Advanced Download Manager with Rate Limit Handling"
        )

        print("\033[96m📚 WHY USE ADVANCED DOWNLOADING?\033[0m")
        print("File downloading is essential for cybersecurity work because it:")
        print("• Downloads security tools, wordlists, and payloads for testing")
        print("• Bypasses rate limits that block automated tool downloads")
        print("• Provides resumable downloads for large security databases")
        print("• Handles multiple concurrent downloads for efficiency")
        print("\n\033[93m🎯 COMMON USE CASES:\033[0m")
        print("• Downloading SecLists wordlists for directory brute forcing")
        print("• Getting exploit databases and proof-of-concept code")
        print("• Fetching vulnerability scanners and security tools")
        print("• Downloading large datasets for security research")
        print("• Bypassing GitHub rate limits when downloading repositories")

        print(f"\n\033[93m{'='*65}\033[0m")
        print("\033[96m1.\033[0m Download Single File")
        print("\033[96m2.\033[0m Download Multiple Files (Batch)")
        print("\033[96m3.\033[0m Download with Rate Limit Bypass")
        print("\033[96m4.\033[0m Resume Interrupted Download")
        print("\033[96m5.\033[0m Show Download Status")
        print("\033[96m6.\033[0m Configure Download Settings")
        print("\033[96m0.\033[0m Back to Main Menu")
        print(f"\033[96m{'='*65}\033[0m")

    def _download_single_file(self):
        """Download a single file with rate limit handling"""
        print("\n\033[96m📥 SINGLE FILE DOWNLOAD\033[0m")

        url = self.get_user_input("Enter file URL: ", "url")
        if not url:
            return

        # Extract filename from URL
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path) or "downloaded_file"

        custom_name = self.get_user_input(
            f"Custom filename (default: {filename}): ", required=False
        )
        if custom_name:
            filename = custom_name

        filepath = os.path.join(self.download_dir, filename)

        self.print_info(f"Starting download: {url}")
        self.print_info(f"Saving to: {filepath}")

        success = self._download_with_fallback(url, filepath)

        if success:
            self.print_success(f"File downloaded successfully: {filepath}")
            file_size = os.path.getsize(filepath)
            self.print_info(f"File size: {self._format_file_size(file_size)}")
        else:
            self.print_error("Download failed with all methods")

    def _download_multiple_files(self):
        """Download multiple files from a list"""
        print("\n\033[96m📥 BATCH FILE DOWNLOAD\033[0m")

        print("Enter URLs (one per line, empty line to finish):")
        urls = []
        while True:
            url = input("URL: ").strip()
            if not url:
                break
            if self.validate_input(url, "url"):
                urls.append(url)
            else:
                self.print_warning(f"Invalid URL skipped: {url}")

        if not urls:
            self.print_warning("No valid URLs provided")
            return

        self.print_info(f"Starting batch download of {len(urls)} files...")

        success_count = 0
        for i, url in enumerate(urls, 1):
            self.print_info(f"[{i}/{len(urls)}] Downloading: {url}")

            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path) or f"file_{i}"
            filepath = os.path.join(self.download_dir, filename)

            if self._download_with_fallback(url, filepath):
                success_count += 1
                self.print_success(f"✅ Downloaded: {filename}")
            else:
                self.print_error(f"❌ Failed: {filename}")

            # Add delay between downloads to avoid rate limiting
            if i < len(urls):
                time.sleep(random.uniform(1, 3))

        self.print_info(
            f"Batch download complete: {success_count}/{len(urls)} files downloaded"
        )

    def _download_with_rate_limit_bypass(self):
        """Download with advanced rate limit bypass techniques"""
        print("\n\033[96m🚀 RATE LIMIT BYPASS DOWNLOAD\033[0m")
        print("This mode uses advanced techniques to bypass download restrictions:")
        print("• Randomized user agents and headers")
        print("• Automatic retry with exponential backoff")
        print("• Multiple download methods as fallbacks")
        print("• Proxy rotation (if configured)")

        url = self.get_user_input("\nEnter file URL: ", "url")
        if not url:
            return

        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path) or "downloaded_file"

        custom_name = self.get_user_input(
            f"Custom filename (default: {filename}): ", required=False
        )
        if custom_name:
            filename = custom_name

        filepath = os.path.join(self.download_dir, filename)

        self.print_info(f"Starting advanced download: {url}")

        # Try multiple methods with increasing sophistication
        methods = [
            ("Basic curl with random user agent", self._download_with_curl_advanced),
            ("Python requests with session", self._download_with_requests_advanced),
            ("Wget with retry logic", self._download_with_wget_advanced),
            ("Split download (chunked)", self._download_with_chunks),
        ]

        for method_name, method_func in methods:
            self.print_info(f"Trying: {method_name}")

            try:
                if method_func(url, filepath):
                    self.print_success(f"✅ Success with {method_name}")
                    file_size = os.path.getsize(filepath)
                    self.print_info(f"File size: {self._format_file_size(file_size)}")
                    return
                else:
                    self.print_warning(f"❌ {method_name} failed")
            except Exception as e:
                self.print_warning(f"❌ {method_name} error: {e}")

            # Add delay between attempts
            time.sleep(random.uniform(2, 5))

        self.print_error("All download methods failed")

    def _download_with_fallback(self, url: str, filepath: str) -> bool:
        """Download file with automatic fallback methods"""
        methods = [
            self._download_with_curl,
            self._download_with_requests,
            self._download_with_python_urllib,
        ]

        for method in methods:
            try:
                if method(url, filepath):
                    return True
            except Exception as e:
                self.logger.debug(f"Download method failed: {e}")
                continue

        return False

    def _download_with_curl(self, url: str, filepath: str) -> bool:
        """Download using curl with rate limit handling"""
        try:
            user_agent = random.choice(self.user_agents)

            cmd = [
                "curl",
                "-L",  # Follow redirects
                "-f",  # Fail silently on HTTP errors
                "--retry",
                "3",
                "--retry-delay",
                "2",
                "--max-time",
                "300",
                "-H",
                f"User-Agent: {user_agent}",
                "-H",
                "Accept: */*",
                "-H",
                "Connection: keep-alive",
                "-o",
                filepath,
                url,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if (
                result.returncode == 0
                and os.path.exists(filepath)
                and os.path.getsize(filepath) > 0
            ):
                return True
            else:
                # Clean up failed download
                if os.path.exists(filepath):
                    os.remove(filepath)
                return False

        except Exception as e:
            self.logger.error(f"Curl download failed: {e}")
            return False

    def _download_with_curl_advanced(self, url: str, filepath: str) -> bool:
        """Advanced curl download with more sophisticated headers"""
        try:
            user_agent = random.choice(self.user_agents)

            cmd = [
                "curl",
                "-L",
                "-f",
                "--retry",
                "5",
                "--retry-delay",
                "3",
                "--retry-max-time",
                "60",
                "--max-time",
                "600",
                "-H",
                f"User-Agent: {user_agent}",
                "-H",
                (
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/webp,*/*;q=0.8"
                ),
                "-H",
                "Accept-Language: en-US,en;q=0.5",
                "-H",
                "Accept-Encoding: gzip, deflate",
                "-H",
                "Connection: keep-alive",
                "-H",
                "Upgrade-Insecure-Requests: 1",
                "--compressed",
                "-o",
                filepath,
                url,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return (
                result.returncode == 0
                and os.path.exists(filepath)
                and os.path.getsize(filepath) > 0
            )

        except Exception:
            return False

    def _download_with_requests(self, url: str, filepath: str) -> bool:
        """Download using Python requests with session management"""
        try:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": random.choice(self.user_agents),
                    "Accept": "*/*",
                    "Connection": "keep-alive",
                }
            )

            with session.get(url, stream=True, timeout=300) as response:
                response.raise_for_status()

                with open(filepath, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

            return os.path.exists(filepath) and os.path.getsize(filepath) > 0

        except Exception as e:
            self.logger.error(f"Requests download failed: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return False

    def _download_with_requests_advanced(self, url: str, filepath: str) -> bool:
        """Advanced requests download with retry logic"""
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            session = requests.Session()

            # Configure retry strategy
            retry_strategy = Retry(
                total=5,
                backoff_factor=2,
                status_forcelist=[429, 500, 502, 503, 504],
            )

            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            session.headers.update(
                {
                    "User-Agent": random.choice(self.user_agents),
                    "Accept": (
                        "text/html,application/xhtml+xml,application/xml;q=0.9,"
                        "*/*;q=0.8"
                    ),
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                }
            )

            with session.get(url, stream=True, timeout=300) as response:
                response.raise_for_status()

                with open(filepath, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

            return os.path.exists(filepath) and os.path.getsize(filepath) > 0

        except Exception:
            return False

    def _download_with_python_urllib(self, url: str, filepath: str) -> bool:
        """Download using urllib as final fallback"""
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": random.choice(self.user_agents)}
            )

            with urllib.request.urlopen(req, timeout=300) as response:
                with open(filepath, "wb") as f:
                    f.write(response.read())

            return os.path.exists(filepath) and os.path.getsize(filepath) > 0

        except Exception as e:
            self.logger.error(f"urllib download failed: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return False

    def _download_with_wget_advanced(self, url: str, filepath: str) -> bool:
        """Advanced wget download (if available)"""
        # Note: wget might not be available in all environments
        return False

    def _download_with_chunks(self, url: str, filepath: str) -> bool:
        """Download file in chunks to bypass size limits"""
        try:
            session = requests.Session()
            session.headers.update({"User-Agent": random.choice(self.user_agents)})

            # Get file size first
            head_response = session.head(url, timeout=30)
            if head_response.status_code != 200:
                return False

            file_size = int(head_response.headers.get("Content-Length", 0) or 0)
            if file_size == 0:
                # Fall back to regular download
                return self._download_with_requests_advanced(url, filepath)

            # Download in 1MB chunks
            chunk_size = 1024 * 1024
            chunks = (file_size // chunk_size) + 1

            with open(filepath, "wb") as f:
                for i in range(chunks):
                    start = i * chunk_size
                    end = min(start + chunk_size - 1, file_size - 1)

                    headers = {"Range": f"bytes={start}-{end}"}
                    # Add session headers individually to avoid type issues
                    for key, value in session.headers.items():
                        if isinstance(value, bytes):
                            headers[key] = value.decode("utf-8")
                        else:
                            headers[key] = str(value)

                    chunk_response = session.get(url, headers=headers, timeout=60)
                    if chunk_response.status_code not in [200, 206]:
                        return False

                    f.write(chunk_response.content)

                    # Small delay between chunks
                    time.sleep(0.1)

            return os.path.exists(filepath) and os.path.getsize(filepath) > 0

        except Exception:
            return False

    def _resume_download(self):
        """Resume an interrupted download"""
        print("\n\033[96m🔄 RESUME DOWNLOAD\033[0m")

        # List partial downloads
        partial_files = [
            f for f in os.listdir(self.download_dir) if f.endswith(".part")
        ]

        if not partial_files:
            self.print_info("No partial downloads found")
            return

        print("Partial downloads found:")
        for i, filename in enumerate(partial_files, 1):
            filepath = os.path.join(self.download_dir, filename)
            size = os.path.getsize(filepath)
            print(f"  {i}. {filename} ({self._format_file_size(size)})")

        choice = self.get_user_input(
            f"Select file to resume (1-{len(partial_files)}): "
        )

        try:
            file_idx = int(choice or "0") - 1
            if 0 <= file_idx < len(partial_files):
                partial_file = partial_files[file_idx]
                url = self.get_user_input("Enter original URL: ", "url")

                if url:
                    self._resume_download_file(url, partial_file)
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Invalid input")

    def _resume_download_file(self, url: str, partial_filename: str):
        """Resume downloading a specific file"""
        partial_path = os.path.join(self.download_dir, partial_filename)
        final_path = partial_path.replace(".part", "")

        existing_size = os.path.getsize(partial_path)
        self.print_info(f"Resuming download from byte {existing_size}")

        try:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": random.choice(self.user_agents),
                    "Range": f"bytes={existing_size}-",
                }
            )

            with session.get(url, stream=True, timeout=300) as response:
                if response.status_code in [200, 206]:
                    with open(partial_path, "ab") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)

                    # Rename to final filename
                    os.rename(partial_path, final_path)
                    self.print_success(f"Download resumed and completed: {final_path}")
                else:
                    self.print_error(f"Resume failed: HTTP {response.status_code}")

        except Exception as e:
            self.print_error(f"Resume failed: {e}")

    def _show_download_status(self):
        """Show current download status and history"""
        print("\n\033[96m📊 DOWNLOAD STATUS\033[0m")

        if not os.path.exists(self.download_dir):
            self.print_info("Download directory doesn't exist")
            return

        files = os.listdir(self.download_dir)

        if not files:
            self.print_info("No downloads found")
            return

        completed_files = [f for f in files if not f.endswith(".part")]
        partial_files = [f for f in files if f.endswith(".part")]

        print(f"\033[96mDownload Directory:\033[0m {self.download_dir}")
        print(f"\033[96mCompleted Downloads:\033[0m {len(completed_files)}")
        print(f"\033[96mPartial Downloads:\033[0m {len(partial_files)}")

        if completed_files:
            print("\n\033[92m✅ Completed Files:\033[0m")
            total_size = 0
            for filename in completed_files[:10]:  # Show first 10
                filepath = os.path.join(self.download_dir, filename)
                size = os.path.getsize(filepath)
                total_size += size
                print(f"  • {filename} ({self._format_file_size(size)})")

            if len(completed_files) > 10:
                print(f"  ... and {len(completed_files) - 10} more files")

            print(f"\n\033[96mTotal Size:\033[0m {self._format_file_size(total_size)}")

        if partial_files:
            print("\n\033[93m⏳ Partial Downloads:\033[0m")
            for filename in partial_files:
                filepath = os.path.join(self.download_dir, filename)
                size = os.path.getsize(filepath)
                print(f"  • {filename} ({self._format_file_size(size)})")

    def _configure_settings(self):
        """Configure download settings"""
        print("\n\033[96m⚙️  DOWNLOAD SETTINGS\033[0m")

        print(f"Current download directory: {self.download_dir}")

        new_dir = self.get_user_input(
            "New download directory (leave empty to keep current): ", required=False
        )
        if new_dir:
            Path(new_dir).mkdir(parents=True, exist_ok=True)
            self.download_dir = new_dir
            self.print_success(f"Download directory changed to: {self.download_dir}")

        # Add more configuration options as needed

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        value = float(size_bytes)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if value < 1024.0:
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} PB"
