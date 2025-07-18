"""
Report Generator Module for Leegion Framework

This module provides comprehensive report generation capabilities
for various security assessment results.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List

import csv
import xml.etree.ElementTree as ET
import sqlite3
from core.logger import setup_logger


class ReportGenerator:
    """Advanced report generator with multiple formats and templates"""

    def __init__(self, config_path: str = "config/config.json"):
        try:
            with open(config_path, "r") as f:
                self.config = json.load(f)
        except Exception:
            self.config = {"output_dir": "./reports/output"}

        self.logger = setup_logger(self.config.get("log_level", "INFO"))
        self.output_dir = self.config.get("output_dir", "./reports/output")
        self.db_path = os.path.join(self.output_dir, "leegion_results.db")
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for storing results"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create tables for different scan types
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    target TEXT,
                    scan_type TEXT,
                    results_json TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    vulnerability_type TEXT,
                    severity TEXT,
                    description TEXT,
                    target TEXT,
                    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (id)
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS discovered_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_type TEXT,
                    asset_value TEXT,
                    source_scan_id INTEGER,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_scan_id) REFERENCES scan_results (id)
                )
            """
            )

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"\033[91m[!]\033[0m Database initialization failed: {e}")

    def store_scan_result(
        self, module_name: str, target: str, scan_type: str, results: Dict[str, Any]
    ) -> int:
        """Store scan result in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                (
                    "INSERT INTO scan_results (timestamp, module_name, target, "
                    "scan_type, results_json) VALUES (?, ?, ?, ?, ?)"
                ),
                (
                    datetime.now().isoformat(),
                    module_name,
                    target,
                    scan_type,
                    json.dumps(results, default=str),
                ),
            )

            scan_id = cursor.lastrowid

            # Store vulnerabilities if present
            if "vulnerabilities" in results:
                for vuln in results["vulnerabilities"]:
                    cursor.execute(
                        (
                            "INSERT INTO vulnerabilities (scan_id, vulnerability_type, "
                            "severity, description, target) VALUES (?, ?, ?, ?, ?)"
                        ),
                        (
                            scan_id,
                            vuln.get("type", "Unknown"),
                            vuln.get("severity", "Unknown"),
                            vuln.get("description", ""),
                            target,
                        ),
                    )

            # Store discovered assets
            if "discovered_hosts" in results:
                for host in results["discovered_hosts"]:
                    cursor.execute(
                        (
                            "INSERT INTO discovered_assets (asset_type, asset_value, "
                            "source_scan_id) VALUES (?, ?, ?)"
                        ),
                        ("host", host, scan_id),
                    )

            if "discovered_subdomains" in results:
                for subdomain in results["discovered_subdomains"]:
                    cursor.execute(
                        (
                            "INSERT INTO discovered_assets (asset_type, asset_value, "
                            "source_scan_id) VALUES (?, ?, ?)"
                        ),
                        ("subdomain", subdomain, scan_id),
                    )

            conn.commit()
            conn.close()

            return scan_id

        except Exception as e:
            self.logger.error(f"Failed to store scan result: {e}")
            return -1

    def interactive_report_generation(self):
        """Interactive report generation interface"""
        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'REPORT GENERATOR'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print("\033[96m1.\033[0m Generate Comprehensive Report")
        print("\033[96m2.\033[0m Generate Vulnerability Report")
        print("\033[96m3.\033[0m Generate Asset Discovery Report")
        print("\033[96m4.\033[0m Generate Executive Summary")
        print("\033[96m5.\033[0m Export Database to JSON")
        print("\033[96m6.\033[0m Generate Custom Report")
        print("\033[96m7.\033[0m View Scan Statistics")
        print("\033[96m8.\033[0m Export Recent Scans")
        print(f"\033[93m{'='*65}\033[0m")

        choice = input("\033[93mSelect report type: \033[0m").strip()

        if choice == "1":
            self.generate_comprehensive_report()
        elif choice == "2":
            self.generate_vulnerability_report()
        elif choice == "3":
            self.generate_asset_discovery_report()
        elif choice == "4":
            self.generate_executive_summary()
        elif choice == "5":
            self.export_database_to_json()
        elif choice == "6":
            self.generate_custom_report()
        elif choice == "7":
            self.display_scan_statistics()
        elif choice == "8":
            self.export_recent_scans()
        else:
            print("\033[91m[!]\033[0m Invalid selection")

    def generate_comprehensive_report(self):
        """Generate comprehensive security assessment report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"comprehensive_report_{timestamp}"

            # Get all scan data
            scan_data = self._get_all_scan_data()

            if not scan_data:
                print(
                    "\033[91m[!]\033[0m No scan data available for " "report generation"
                )
                return

            # Generate in multiple formats
            formats = (
                input("Select formats (json,html,pdf,csv - comma separated): ")
                .strip()
                .lower()
            )
            if not formats:
                formats = "json,html"

            format_list = [fmt.strip() for fmt in formats.split(",")]

            for fmt in format_list:
                if fmt == "json":
                    self._generate_json_report(scan_data, report_name)
                elif fmt == "html":
                    self._generate_html_report(scan_data, report_name)
                elif fmt == "csv":
                    self._generate_csv_report(scan_data, report_name)
                elif fmt == "xml":
                    self._generate_xml_report(scan_data, report_name)
                elif fmt == "pdf":
                    self._generate_pdf_report(scan_data, report_name)
                else:
                    print(f"\033[93m[!]\033[0m Unsupported format: {fmt}")

            print(
                f"\033[92m[+]\033[0m Comprehensive report generated: " f"{report_name}"
            )

        except Exception as e:
            print(f"\033[91m[!]\033[0m Report generation failed: {e}")
            self.logger.error(f"Comprehensive report generation error: {e}")

    def generate_vulnerability_report(self):
        """Generate focused vulnerability report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"vulnerability_report_{timestamp}"

            vulnerabilities = self._get_all_vulnerabilities()

            if not vulnerabilities:
                print("\033[91m[!]\033[0m No vulnerabilities found in database")
                return

            # Group vulnerabilities by severity
            vuln_by_severity = {
                "CRITICAL": [],
                "HIGH": [],
                "MEDIUM": [],
                "LOW": [],
                "INFO": [],
            }

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "UNKNOWN").upper()
                if severity in vuln_by_severity:
                    vuln_by_severity[severity].append(vuln)
                else:
                    vuln_by_severity["INFO"].append(vuln)

            # Generate vulnerability-focused report
            report_data = {
                "report_type": "vulnerability_assessment",
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_vulnerabilities": len(vulnerabilities),
                    "critical": len(vuln_by_severity["CRITICAL"]),
                    "high": len(vuln_by_severity["HIGH"]),
                    "medium": len(vuln_by_severity["MEDIUM"]),
                    "low": len(vuln_by_severity["LOW"]),
                    "info": len(vuln_by_severity["INFO"]),
                },
                "vulnerabilities_by_severity": vuln_by_severity,
                "risk_score": self._calculate_risk_score(vuln_by_severity),
            }

            self._generate_json_report(report_data, report_name)
            self._generate_vulnerability_html_report(report_data, report_name)

            print(f"\033[92m[+]\033[0m Vulnerability report generated: {report_name}")

        except Exception as e:
            print(f"\033[91m[!]\033[0m Vulnerability report generation failed: {e}")

    def generate_asset_discovery_report(self):
        """Generate asset discovery report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"asset_discovery_{timestamp}"

            assets = self._get_all_assets()

            if not assets:
                print("\033[91m[!]\033[0m No assets found in database")
                return

            # Group assets by type
            assets_by_type = {}
            for asset in assets:
                asset_type = asset.get("asset_type", "unknown")
                if asset_type not in assets_by_type:
                    assets_by_type[asset_type] = []
                assets_by_type[asset_type].append(asset)

            report_data = {
                "report_type": "asset_discovery",
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_assets": len(assets),
                    "asset_types": list(assets_by_type.keys()),
                    "assets_by_type_count": {
                        k: len(v) for k, v in assets_by_type.items()
                    },
                },
                "assets_by_type": assets_by_type,
            }

            self._generate_json_report(report_data, report_name)
            self._generate_asset_csv_report(assets, report_name)

            print(f"\033[92m[+]\033[0m Asset discovery report generated: {report_name}")

        except Exception as e:
            print(f"\033[91m[!]\033[0m Asset discovery report generation failed: {e}")

    def generate_executive_summary(self):
        """Generate executive summary report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"executive_summary_{timestamp}"

            # Get summary statistics
            stats = self._get_summary_statistics()

            summary_data = {
                "report_type": "executive_summary",
                "generated_at": datetime.now().isoformat(),
                "assessment_period": self._get_assessment_period(),
                "key_findings": {
                    "total_scans_performed": stats.get("total_scans", 0),
                    "targets_assessed": stats.get("unique_targets", 0),
                    "vulnerabilities_found": stats.get("total_vulnerabilities", 0),
                    "critical_issues": stats.get("critical_vulnerabilities", 0),
                    "assets_discovered": stats.get("total_assets", 0),
                },
                "risk_assessment": self._generate_risk_assessment(),
                "recommendations": self._generate_recommendations(stats),
            }

            self._generate_json_report(summary_data, report_name)
            self._generate_executive_html_report(summary_data, report_name)

            print(f"\033[92m[+]\033[0m Executive summary generated: {report_name}")

        except Exception as e:
            print(f"\033[91m[!]\033[0m Executive summary generation failed: {e}")

    def export_database_to_json(self):
        """Export entire database to JSON"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"database_export_{timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)

            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "scan_results": self._get_all_scan_data(),
                "vulnerabilities": self._get_all_vulnerabilities(),
                "assets": self._get_all_assets(),
                "statistics": self._get_summary_statistics(),
            }

            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            print(f"\033[92m[+]\033[0m Database exported to: {filepath}")

        except Exception as e:
            print(f"\033[91m[!]\033[0m Database export failed: {e}")

    def generate_custom_report(self):
        """Generate custom report based on user criteria"""
        try:
            print("\nCustom Report Builder")
            print("1. Filter by module")
            print("2. Filter by date range")
            print("3. Filter by target")
            print("4. Filter by scan type")

            filters = {}

            filter_choice = input("Select filter type (1-4): ").strip()

            if filter_choice == "1":
                module = input("Enter module name: ").strip()
                if module:
                    filters["module_name"] = module
            elif filter_choice == "2":
                start_date = input("Enter start date (YYYY-MM-DD): ").strip()
                end_date = input("Enter end date (YYYY-MM-DD): ").strip()
                if start_date and end_date:
                    filters["date_range"] = (start_date, end_date)
            elif filter_choice == "3":
                target = input("Enter target: ").strip()
                if target:
                    filters["target"] = target
            elif filter_choice == "4":
                scan_type = input("Enter scan type: ").strip()
                if scan_type:
                    filters["scan_type"] = scan_type

            # Get filtered data
            filtered_data = self._get_filtered_scan_data(filters)

            if not filtered_data:
                print("\033[91m[!]\033[0m No data matches the specified filters")
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"custom_report_{timestamp}"

            self._generate_json_report(filtered_data, report_name)

            print(f"\033[92m[+]\033[0m Custom report generated: {report_name}")

        except Exception as e:
            print(f"\033[91m[!]\033[0m Custom report generation failed: {e}")

    def display_scan_statistics(self):
        """Display scan statistics"""
        try:
            stats = self._get_summary_statistics()

            print(f"\n\033[93m{'SCAN STATISTICS'.center(60)}\033[0m")
            print(f"\033[93m{'-'*60}\033[0m")
            print(f"\033[96mTotal Scans:\033[0m {stats.get('total_scans', 0)}")
            print(f"\033[96mUnique Targets:\033[0m {stats.get('unique_targets', 0)}")
            print(
                f"\033[96mTotal Vulnerabilities:\033[0m "
                f"{stats.get('total_vulnerabilities', 0)}"
            )
            print(
                f"\033[96mCritical Vulnerabilities:\033[0m "
                f"{stats.get('critical_vulnerabilities', 0)}"
            )
            print(f"\033[96mTotal Assets:\033[0m {stats.get('total_assets', 0)}")
            print(
                f"\033[96mScan Types Used:\033[0m "
                f"{', '.join(stats.get('scan_types', []))}"
            )
            print(
                f"\033[96mModules Used:\033[0m "
                f"{', '.join(stats.get('modules_used', []))}"
            )

            # Recent activity
            recent_scans = self._get_recent_scans(limit=5)
            if recent_scans:
                print("\n\033[93mRecent Scans:\033[0m")
                for scan in recent_scans:
                    timestamp = scan.get("timestamp", "")[:19].replace("T", " ")
                    print(
                        f"  {timestamp} - {scan.get('module_name')} on {scan.get('target')}"
                    )

        except Exception as e:
            print(f"\033[91m[!]\033[0m Failed to display statistics: {e}")

    def export_recent_scans(self):
        """Export recent scans"""
        try:
            days = input("Enter number of days (default: 7): ").strip()
            if not days or not days.isdigit():
                days = 7
            else:
                days = int(days)

            recent_scans = self._get_recent_scans_by_days(days)

            if not recent_scans:
                print(f"\033[91m[!]\033[0m No scans found in the last {days} days")
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recent_scans_{days}days_{timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)

            with open(filepath, "w") as f:
                json.dump(recent_scans, f, indent=2, default=str)

            print(f"\033[92m[+]\033[0m Recent scans exported to: {filepath}")

        except Exception as e:
            print(f"\033[91m[!]\033[0m Recent scans export failed: {e}")

    def _get_all_scan_data(self) -> List[Dict[str, Any]]:
        """Get all scan data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id, timestamp, module_name, target, scan_type, results_json
                FROM scan_results
                ORDER BY timestamp DESC
            """
            )

            rows = cursor.fetchall()
            conn.close()

            scan_data = []
            for row in rows:
                try:
                    results = json.loads(row[5]) if row[5] else {}
                    scan_data.append(
                        {
                            "id": row[0],
                            "timestamp": row[1],
                            "module_name": row[2],
                            "target": row[3],
                            "scan_type": row[4],
                            "results": results,
                        }
                    )
                except json.JSONDecodeError:
                    continue

            return scan_data

        except Exception as e:
            self.logger.error(f"Failed to get scan data: {e}")
            return []

    def _get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all vulnerabilities from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT v.id, v.vulnerability_type, v.severity, v.description, v.target, v.discovered_at,
                       s.module_name, s.scan_type
                FROM vulnerabilities v
                JOIN scan_results s ON v.scan_id = s.id
                ORDER BY v.discovered_at DESC
            """
            )

            rows = cursor.fetchall()
            conn.close()

            vulnerabilities = []
            for row in rows:
                vulnerabilities.append(
                    {
                        "id": row[0],
                        "type": row[1],
                        "severity": row[2],
                        "description": row[3],
                        "target": row[4],
                        "discovered_at": row[5],
                        "module_name": row[6],
                        "scan_type": row[7],
                    }
                )

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    def _get_all_assets(self) -> List[Dict[str, Any]]:
        """Get all discovered assets from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT a.id, a.asset_type, a.asset_value, a.first_seen, a.last_seen,
                       s.module_name, s.target
                FROM discovered_assets a
                JOIN scan_results s ON a.source_scan_id = s.id
                ORDER BY a.first_seen DESC
            """
            )

            rows = cursor.fetchall()
            conn.close()

            assets = []
            for row in rows:
                assets.append(
                    {
                        "id": row[0],
                        "asset_type": row[1],
                        "asset_value": row[2],
                        "first_seen": row[3],
                        "last_seen": row[4],
                        "source_module": row[5],
                        "source_target": row[6],
                    }
                )

            return assets

        except Exception as e:
            self.logger.error(f"Failed to get assets: {e}")
            return []

    def _get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scan_results")
            total_scans = cursor.fetchone()[0]

            # Unique targets
            cursor.execute("SELECT COUNT(DISTINCT target) FROM scan_results")
            unique_targets = cursor.fetchone()[0]

            # Total vulnerabilities
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulnerabilities = cursor.fetchone()[0]

            # Critical vulnerabilities
            cursor.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'"
            )
            critical_vulnerabilities = cursor.fetchone()[0]

            # Total assets
            cursor.execute("SELECT COUNT(*) FROM discovered_assets")
            total_assets = cursor.fetchone()[0]

            # Scan types
            cursor.execute(
                "SELECT DISTINCT scan_type FROM scan_results WHERE scan_type IS NOT NULL"
            )
            scan_types = [row[0] for row in cursor.fetchall()]

            # Modules used
            cursor.execute("SELECT DISTINCT module_name FROM scan_results")
            modules_used = [row[0] for row in cursor.fetchall()]

            conn.close()

            return {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulnerabilities,
                "total_assets": total_assets,
                "scan_types": scan_types,
                "modules_used": modules_used,
            }

        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}

    def _get_filtered_scan_data(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get filtered scan data based on criteria"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            query = """
                SELECT id, timestamp, module_name, target, scan_type, results_json
                FROM scan_results
                WHERE 1=1
            """
            params = []

            if "module_name" in filters:
                query += " AND module_name = ?"
                params.append(filters["module_name"])

            if "target" in filters:
                query += " AND target LIKE ?"
                params.append(f"%{filters['target']}%")

            if "scan_type" in filters:
                query += " AND scan_type = ?"
                params.append(filters["scan_type"])

            if "date_range" in filters:
                start_date, end_date = filters["date_range"]
                query += " AND timestamp BETWEEN ? AND ?"
                params.extend([start_date, end_date])

            query += " ORDER BY timestamp DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            filtered_data = []
            for row in rows:
                try:
                    results = json.loads(row[5]) if row[5] else {}
                    filtered_data.append(
                        {
                            "id": row[0],
                            "timestamp": row[1],
                            "module_name": row[2],
                            "target": row[3],
                            "scan_type": row[4],
                            "results": results,
                        }
                    )
                except json.JSONDecodeError:
                    continue

            return filtered_data

        except Exception as e:
            self.logger.error(f"Failed to get filtered data: {e}")
            return []

    def _get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT timestamp, module_name, target, scan_type
                FROM scan_results
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (limit,),
            )

            rows = cursor.fetchall()
            conn.close()

            recent_scans = []
            for row in rows:
                recent_scans.append(
                    {
                        "timestamp": row[0],
                        "module_name": row[1],
                        "target": row[2],
                        "scan_type": row[3],
                    }
                )

            return recent_scans

        except Exception as e:
            self.logger.error(f"Failed to get recent scans: {e}")
            return []

    def _get_recent_scans_by_days(self, days: int) -> List[Dict[str, Any]]:
        """Get scans from the last N days"""
        try:
            from datetime import timedelta

            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id, timestamp, module_name, target, scan_type, results_json
                FROM scan_results
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
            """,
                (cutoff_date,),
            )

            rows = cursor.fetchall()
            conn.close()

            recent_scans = []
            for row in rows:
                try:
                    results = json.loads(row[5]) if row[5] else {}
                    recent_scans.append(
                        {
                            "id": row[0],
                            "timestamp": row[1],
                            "module_name": row[2],
                            "target": row[3],
                            "scan_type": row[4],
                            "results": results,
                        }
                    )
                except json.JSONDecodeError:
                    continue

            return recent_scans

        except Exception as e:
            self.logger.error(f"Failed to get recent scans by days: {e}")
            return []

    def _calculate_risk_score(self, vuln_by_severity: Dict[str, List]) -> float:
        """Calculate overall risk score"""
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}

        total_score = 0
        for severity, vulns in vuln_by_severity.items():
            weight = weights.get(severity, 1)
            total_score += len(vulns) * weight

        # Normalize to 0-100 scale
        max_possible = sum(
            len(vulns) * weights.get(sev, 1) for sev, vulns in vuln_by_severity.items()
        )
        if max_possible == 0:
            return 0.0

        return min(100.0, (total_score / max_possible) * 100)

    def _get_assessment_period(self) -> Dict[str, str]:
        """Get assessment period from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM scan_results")
            result = cursor.fetchone()
            conn.close()

            if result and result[0] and result[1]:
                return {"start_date": result[0][:10], "end_date": result[1][:10]}
            else:
                today = datetime.now().strftime("%Y-%m-%d")
                return {"start_date": today, "end_date": today}
        except Exception:
            today = datetime.now().strftime("%Y-%m-%d")
            return {"start_date": today, "end_date": today}

    def _generate_risk_assessment(self) -> Dict[str, Any]:
        """Generate risk assessment summary"""
        vulnerabilities = self._get_all_vulnerabilities()

        risk_levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").upper()
            if severity in risk_levels:
                risk_levels[severity] += 1

        total_vulns = sum(risk_levels.values())

        if total_vulns == 0:
            overall_risk = "LOW"
        elif risk_levels["CRITICAL"] > 0:
            overall_risk = "CRITICAL"
        elif risk_levels["HIGH"] > 2:
            overall_risk = "HIGH"
        elif risk_levels["HIGH"] > 0 or risk_levels["MEDIUM"] > 5:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        return {
            "overall_risk_level": overall_risk,
            "vulnerability_breakdown": risk_levels,
            "total_vulnerabilities": total_vulns,
            "risk_score": self._calculate_risk_score(
                {
                    "CRITICAL": [None] * risk_levels["CRITICAL"],
                    "HIGH": [None] * risk_levels["HIGH"],
                    "MEDIUM": [None] * risk_levels["MEDIUM"],
                    "LOW": [None] * risk_levels["LOW"],
                }
            ),
        }

    def _generate_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        critical_vulns = stats.get("critical_vulnerabilities", 0)
        total_vulns = stats.get("total_vulnerabilities", 0)

        if critical_vulns > 0:
            recommendations.append(
                f"Immediately address {critical_vulns} critical vulnerabilities"
            )

        if total_vulns > 10:
            recommendations.append("Implement a vulnerability management program")
            recommendations.append("Consider automated security scanning solutions")

        if stats.get("total_scans", 0) > 0:
            recommendations.append("Continue regular security assessments")
            recommendations.append("Implement security monitoring and alerting")

        # Default recommendations
        recommendations.extend(
            [
                "Keep all systems and software up to date",
                "Implement strong access controls and authentication",
                "Regular security awareness training for staff",
                "Develop and test incident response procedures",
            ]
        )

        return recommendations

    def _generate_json_report(self, data: Any, report_name: str):
        """Generate JSON report"""
        filepath = os.path.join(self.output_dir, f"{report_name}.json")

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

        print(f"\033[92m[+]\033[0m JSON report saved: {filepath}")

    def _generate_csv_report(self, data: List[Dict], report_name: str):
        """Generate CSV report"""
        if not data:
            return

        filepath = os.path.join(self.output_dir, f"{report_name}.csv")

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)

            # Write headers
            if data:
                headers = [
                    "Timestamp",
                    "Module",
                    "Target",
                    "Scan Type",
                    "Results Summary",
                ]
                writer.writerow(headers)

                # Write data
                for item in data:
                    results_summary = f"{len(item.get('results', {}))} items"
                    writer.writerow(
                        [
                            item.get("timestamp", ""),
                            item.get("module_name", ""),
                            item.get("target", ""),
                            item.get("scan_type", ""),
                            results_summary,
                        ]
                    )

        print(f"\033[92m[+]\033[0m CSV report saved: {filepath}")

    def _generate_xml_report(self, data: Any, report_name: str):
        """Generate XML report"""
        filepath = os.path.join(self.output_dir, f"{report_name}.xml")

        root = ET.Element("leegion_report")

        if isinstance(data, list):
            for item in data:
                scan_elem = ET.SubElement(root, "scan")
                for key, value in item.items():
                    if key != "results":
                        elem = ET.SubElement(scan_elem, key)
                        elem.text = str(value)
        elif isinstance(data, dict):
            for key, value in data.items():
                elem = ET.SubElement(root, key)
                elem.text = str(value)

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)

        print(f"\033[92m[+]\033[0m XML report saved: {filepath}")

    def _generate_html_report(self, data: Any, report_name: str):
        """Generate HTML report"""
        filepath = os.path.join(self.output_dir, f"{report_name}.html")

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Leegion Framework - Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .critical {{ color: #e74c3c; font-weight: bold; }}
                .high {{ color: #f39c12; font-weight: bold; }}
                .medium {{ color: #f1c40f; font-weight: bold; }}
                .low {{ color: #27ae60; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Leegion Framework Security Assessment Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <p>Comprehensive security assessment report generated by Leegion Framework.</p>

                {self._format_html_summary(data)}
            </div>

            <div class="section">
                <h2>Detailed Findings</h2>
                {self._format_html_details(data)}
            </div>
        </body>
        </html>
        """

        with open(filepath, "w") as f:
            f.write(html_content)

        print(f"\033[92m[+]\033[0m HTML report saved: {filepath}")

    def _generate_vulnerability_html_report(self, data: Dict, report_name: str):
        """Generate vulnerability-focused HTML report"""
        filepath = os.path.join(self.output_dir, f"{report_name}.html")

        summary = data.get("summary", {})
        vuln_by_severity = data.get("vulnerabilities_by_severity", {})

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #c0392b; color: white; padding: 20px; text-align: center; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; }}
                .critical {{ background-color: #e74c3c; color: white; padding: 10px; margin: 5px; }}
                .high {{ background-color: #f39c12; color: white; padding: 10px; margin: 5px; }}
                .medium {{ background-color: #f1c40f; color: black; padding: 10px; margin: 5px; }}
                .low {{ background-color: #27ae60; color: white; padding: 10px; margin: 5px; }}
                .info {{ background-color: #3498db; color: white; padding: 10px; margin: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Vulnerability Assessment Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <div class="summary">
                <h2>Vulnerability Summary</h2>
                <div class="critical">Critical: {summary.get('critical', 0)}</div>
                <div class="high">High: {summary.get('high', 0)}</div>
                <div class="medium">Medium: {summary.get('medium', 0)}</div>
                <div class="low">Low: {summary.get('low', 0)}</div>
                <div class="info">Info: {summary.get('info', 0)}</div>
                <p><strong>Risk Score:</strong> {data.get('risk_score', 0):.1f}/100</p>
            </div>

            {self._format_vulnerability_details_html(vuln_by_severity)}
        </body>
        </html>
        """

        with open(filepath, "w") as f:
            f.write(html_content)

        print(f"\033[92m[+]\033[0m Vulnerability HTML report saved: {filepath}")

    def _generate_executive_html_report(self, data: Dict, report_name: str):
        """Generate executive summary HTML report"""
        filepath = os.path.join(self.output_dir, f"{report_name}.html")

        key_findings = data.get("key_findings", {})
        risk_assessment = data.get("risk_assessment", {})
        recommendations = data.get("recommendations", [])

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Executive Summary Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
                .header {{ background-color: #34495e; color: white; padding: 20px; text-align: center; }}
                .findings {{ background-color: #ecf0f1; padding: 20px; margin: 20px 0; }}
                .recommendations {{ background-color: #e8f5e8; padding: 20px; margin: 20px 0; }}
                .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #3498db; color: white; border-radius: 5px; }}
                .risk-high {{ background-color: #e74c3c; }}
                .risk-medium {{ background-color: #f39c12; }}
                .risk-low {{ background-color: #27ae60; }}
                ul {{ list-style-type: none; padding: 0; }}
                li {{ padding: 5px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Executive Summary</h1>
                <p>Security Assessment Overview</p>
                <p>Period: {data.get('assessment_period', {}).get('start_date', 'N/A')} to {data.get('assessment_period', {}).get('end_date', 'N/A')}</p>
            </div>

            <div class="findings">
                <h2>Key Findings</h2>
                <div class="metric">Scans: {key_findings.get('total_scans_performed', 0)}</div>
                <div class="metric">Targets: {key_findings.get('targets_assessed', 0)}</div>
                <div class="metric">Vulnerabilities: {key_findings.get('vulnerabilities_found', 0)}</div>
                <div class="metric">Critical Issues: {key_findings.get('critical_issues', 0)}</div>
                <div class="metric">Assets: {key_findings.get('assets_discovered', 0)}</div>

                <h3>Risk Assessment</h3>
                <p class="risk-{risk_assessment.get('overall_risk_level', 'low').lower()}">
                    Overall Risk Level: {risk_assessment.get('overall_risk_level', 'Unknown')}
                </p>
                <p>Risk Score: {risk_assessment.get('risk_score', 0):.1f}/100</p>
            </div>

            <div class="recommendations">
                <h2>Recommendations</h2>
                <ul>
        """

        for recommendation in recommendations:
            html_content += f"<li>• {recommendation}</li>"

        html_content += """
                </ul>
            </div>
        </body>
        </html>
        """

        with open(filepath, "w") as f:
            f.write(html_content)

        print(f"\033[92m[+]\033[0m Executive HTML report saved: {filepath}")

    def _generate_asset_csv_report(self, assets: List[Dict], report_name: str):
        """Generate asset discovery CSV report"""
        filepath = os.path.join(self.output_dir, f"{report_name}.csv")

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)

            # Write headers
            writer.writerow(
                [
                    "Asset Type",
                    "Asset Value",
                    "First Seen",
                    "Last Seen",
                    "Source Module",
                    "Source Target",
                ]
            )

            # Write asset data
            for asset in assets:
                writer.writerow(
                    [
                        asset.get("asset_type", ""),
                        asset.get("asset_value", ""),
                        asset.get("first_seen", ""),
                        asset.get("last_seen", ""),
                        asset.get("source_module", ""),
                        asset.get("source_target", ""),
                    ]
                )

        print(f"\033[92m[+]\033[0m Asset CSV report saved: {filepath}")

    def _generate_pdf_report(self, data: Any, report_name: str):
        """Generate PDF report using HTML to PDF conversion"""
        # First generate HTML report
        html_report_name = f"{report_name}_temp"
        self._generate_html_report(data, html_report_name)

        html_filepath = os.path.join(self.output_dir, f"{html_report_name}.html")
        pdf_filepath = os.path.join(self.output_dir, f"{report_name}.pdf")

        try:
            # Try using wkhtmltopdf if available
            import subprocess

            result = subprocess.run(
                ["wkhtmltopdf", "--version"], capture_output=True, text=True
            )
            if result.returncode == 0:
                subprocess.run(["wkhtmltopdf", html_filepath, pdf_filepath], check=True)
                print(f"\033[92m[+]\033[0m PDF report generated: {pdf_filepath}")
                # Clean up temporary HTML file
                os.remove(html_filepath)
            else:
                raise FileNotFoundError("wkhtmltopdf not found")

        except (FileNotFoundError, subprocess.CalledProcessError):
            print("\033[93m[!]\033[0m PDF generation requires wkhtmltopdf")
            print("\033[96m[i]\033[0m Install with: sudo apt-get install wkhtmltopdf")
            print(
                "\033[96m[i]\033[0m You can manually convert HTML to PDF using browser print function"
            )

    def _format_html_summary(self, data: Any) -> str:
        """Format data for HTML summary section"""
        if isinstance(data, list) and data:
            return f"<p>Total scan results: {len(data)}</p>"
        elif isinstance(data, dict):
            return f"<p>Report contains {len(data)} sections</p>"
        return "<p>No summary data available</p>"

    def _format_html_details(self, data: Any) -> str:
        """Format data for HTML details section"""
        if isinstance(data, list):
            html = "<table><tr><th>Timestamp</th><th>Module</th><th>Target</th><th>Type</th></tr>"
            for item in data[:20]:  # Limit to first 20 items
                html += f"""
                <tr>
                    <td>{item.get('timestamp', '')[:19]}</td>
                    <td>{item.get('module_name', '')}</td>
                    <td>{item.get('target', '')}</td>
                    <td>{item.get('scan_type', '')}</td>
                </tr>
                """
            html += "</table>"
            if len(data) > 20:
                html += f"<p>... and {len(data) - 20} more results</p>"
            return html
        return "<p>No detailed data available</p>"

    def _format_vulnerability_details_html(self, vuln_by_severity: Dict) -> str:
        """Format vulnerability details for HTML"""
        html = ""

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            vulns = vuln_by_severity.get(severity, [])
            if vulns:
                html += f"<h3>{severity} Vulnerabilities ({len(vulns)})</h3>"
                html += "<table><tr><th>Type</th><th>Description</th><th>Target</th><th>Discovered</th></tr>"

                for vuln in vulns:
                    html += f"""
                    <tr>
                        <td>{vuln.get('type', '')}</td>
                        <td>{vuln.get('description', '')}</td>
                        <td>{vuln.get('target', '')}</td>
                        <td>{vuln.get('discovered_at', '')[:19]}</td>
                    </tr>
                    """

                html += "</table>"

        return html
