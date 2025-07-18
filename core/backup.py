"""
Backup and recovery system for Leegion Framework

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import os
import json
import shutil
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib
from core.security import SecurityManager


class BackupManager:
    """Comprehensive backup and recovery system"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.backup_dir = Path(config.get("backup_dir", "./backups"))
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.security_manager = SecurityManager()

        # Backup components
        self.backup_components: Dict[str, Dict[str, Any]] = {
            "config": {
                "paths": ["~/.config/leegion"],
                "description": "User configuration and settings",
            },
            "results": {
                "paths": [config.get("output_dir", "./reports")],
                "description": "Scan results and reports",
            },
            "logs": {"paths": ["./logs"], "description": "Framework logs"},
            "vpn_configs": {
                "paths": [config.get("vpn_config_dir", "./vpn_configs")],
                "description": "VPN configuration files",
            },
            "wordlists": {"paths": ["./wordlists"], "description": "Custom wordlists"},
        }

    def create_backup(
        self, components: Optional[List[str]] = None, include_encrypted: bool = True
    ) -> str:
        """
        Create a comprehensive backup

        Args:
            components: List of components to backup (None = all)
            include_encrypted: Whether to include encrypted data

        Returns:
            Path to backup file
        """
        if components is None:
            components = list(self.backup_components.keys())

        # Create backup timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"leegion_backup_{timestamp}.zip"
        backup_path = self.backup_dir / backup_filename

        # Create temporary directory for backup
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create backup manifest
            manifest = {
                "backup_timestamp": timestamp,
                "framework_version": "2.0.0",
                "components": components,
                "include_encrypted": include_encrypted,
                "files": [],
            }

            # Backup each component
            for component in components:
                if component not in self.backup_components:
                    continue

                component_info = self.backup_components[component]
                component_dir = temp_path / component
                component_dir.mkdir(exist_ok=True)

                for path in component_info["paths"]:
                    source_path = Path(path).expanduser()
                    if source_path.exists():
                        self._backup_path(source_path, component_dir, include_encrypted)

            # Save manifest
            with open(temp_path / "manifest.json", "w") as f:
                json.dump(manifest, f, indent=2)

            # Create ZIP archive
            with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(temp_path):
                    for file in files:
                        file_path = Path(root) / file
                        arc_path = file_path.relative_to(temp_path)
                        zipf.write(file_path, arc_path)

            # Calculate checksum
            checksum = self._calculate_file_checksum(backup_path)

            # Save backup info
            backup_info = {
                "filename": backup_filename,
                "timestamp": timestamp,
                "size": backup_path.stat().st_size,
                "checksum": checksum,
                "components": components,
                "include_encrypted": include_encrypted,
            }

            info_path = self.backup_dir / f"{backup_filename}.info"
            with open(info_path, "w") as f:
                json.dump(backup_info, f, indent=2)

        return str(backup_path)

    def _backup_path(self, source_path: Path, dest_dir: Path, include_encrypted: bool):
        """Backup a specific path"""
        if source_path.is_file():
            # Handle encrypted files
            if not include_encrypted and self._is_encrypted_file(source_path):
                return

            dest_file = dest_dir / source_path.name
            shutil.copy2(source_path, dest_file)

        elif source_path.is_dir():
            # Create subdirectory
            sub_dir = dest_dir / source_path.name
            sub_dir.mkdir(exist_ok=True)

            # Copy contents
            for item in source_path.iterdir():
                if item.is_file():
                    if not include_encrypted and self._is_encrypted_file(item):
                        continue
                    shutil.copy2(item, sub_dir / item.name)
                elif item.is_dir():
                    shutil.copytree(item, sub_dir / item.name, dirs_exist_ok=True)

    def _is_encrypted_file(self, file_path: Path) -> bool:
        """Check if file contains encrypted data"""
        try:
            with open(file_path, "r") as f:
                content = f.read()
                return content.startswith("enc:")
        except Exception:
            return False

    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def restore_backup(
        self,
        backup_path: str,
        components: Optional[List[str]] = None,
        verify_checksum: bool = True,
    ) -> bool:
        """
        Restore from backup

        Args:
            backup_path: Path to backup file
            components: Components to restore (None = all)
            verify_checksum: Whether to verify file integrity

        Returns:
            True if successful
        """
        backup_path_obj = Path(backup_path)
        if not backup_path_obj.exists():
            return False

        # Verify checksum if requested
        if verify_checksum:
            info_path = backup_path_obj.with_suffix(".info")
            if info_path.exists():
                with open(info_path, "r") as f:
                    backup_info = json.load(f)

                expected_checksum = backup_info.get("checksum")
                if expected_checksum:
                    actual_checksum = self._calculate_file_checksum(backup_path_obj)
                    if actual_checksum != expected_checksum:
                        return False

        try:
            # Extract backup
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                with zipfile.ZipFile(backup_path_obj, "r") as zipf:
                    zipf.extractall(temp_path)

                # Load manifest
                manifest_path = temp_path / "manifest.json"
                if manifest_path.exists():
                    with open(manifest_path, "r") as f:
                        manifest = json.load(f)

                    backup_components = manifest.get("components", [])
                    if components is None:
                        components = backup_components
                    else:
                        # Only restore requested components that exist in backup
                        components = [c for c in components if c in backup_components]

                # Restore components
                if components:
                    for component in components:
                        component_dir = temp_path / component
                        if component_dir.exists():
                            self._restore_component(component, component_dir)

            return True

        except Exception:
            return False

    def _restore_component(self, component: str, component_dir: Path):
        """Restore a specific component"""
        if component not in self.backup_components:
            return

        component_info = self.backup_components[component]

        for path in component_info["paths"]:
            dest_path = Path(path).expanduser()

            if component_dir.is_dir():
                # Restore directory contents
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.copytree(component_dir, dest_path, dirs_exist_ok=True)

    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups"""
        backups = []

        for info_file in self.backup_dir.glob("*.info"):
            try:
                with open(info_file, "r") as f:
                    backup_info: Dict[str, Any] = json.load(f)

                # Check if backup file still exists
                backup_file = self.backup_dir / backup_info["filename"]
                if backup_file.exists():
                    backup_info["exists"] = True
                    backup_info["file_size"] = backup_file.stat().st_size
                else:
                    backup_info["exists"] = False

                backups.append(backup_info)

            except Exception:
                continue

        # Sort by timestamp (newest first)
        backups.sort(key=lambda x: x["timestamp"], reverse=True)
        return backups

    def delete_backup(self, backup_filename: str) -> bool:
        """Delete a backup"""
        try:
            backup_path = self.backup_dir / backup_filename
            info_path = self.backup_dir / f"{backup_filename}.info"

            if backup_path.exists():
                backup_path.unlink()

            if info_path.exists():
                info_path.unlink()

            return True

        except Exception:
            return False

    def export_results(
        self, output_format: str = "json", components: Optional[List[str]] = None
    ) -> str:
        """
        Export results in various formats

        Args:
            output_format: 'json', 'csv', 'xml'
            components: Components to export (None = all)

        Returns:
            Path to exported file
        """
        if components is None:
            components = ["results", "config"]

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_filename = f"leegion_export_{timestamp}.{output_format}"
        export_path = self.backup_dir / export_filename

        export_data = {
            "export_timestamp": timestamp,
            "framework_version": "2.0.0",
            "components": {},
        }

        # Export each component
        for component in components:
            if component in self.backup_components:
                component_data = self._export_component(component)
                export_data["components"][component] = component_data

        # Write export file
        if output_format == "json":
            with open(export_path, "w") as f:
                json.dump(export_data, f, indent=2)
        elif output_format == "csv":
            self._export_to_csv(export_data, export_path)
        elif output_format == "xml":
            self._export_to_xml(export_data, export_path)

        return str(export_path)

    def _export_component(self, component: str) -> Dict[str, Any]:
        """Export a specific component"""
        component_data: Dict[str, Any] = {
            "description": self.backup_components[component]["description"],
            "files": [],
        }

        for path in self.backup_components[component]["paths"]:
            source_path = Path(path).expanduser()
            if source_path.exists():
                if source_path.is_file():
                    component_data["files"].append(
                        {
                            "path": str(source_path),
                            "size": source_path.stat().st_size,
                            "modified": source_path.stat().st_mtime,
                        }
                    )
                elif source_path.is_dir():
                    for file_path in source_path.rglob("*"):
                        if file_path.is_file():
                            component_data["files"].append(
                                {
                                    "path": str(file_path),
                                    "size": file_path.stat().st_size,
                                    "modified": file_path.stat().st_mtime,
                                }
                            )

        return component_data

    def _export_to_csv(self, data: Dict[str, Any], file_path: Path):
        """Export data to CSV format"""
        import csv

        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Component", "File", "Size", "Modified"])

            for component, component_data in data["components"].items():
                for file_info in component_data["files"]:
                    writer.writerow(
                        [
                            component,
                            file_info["path"],
                            file_info["size"],
                            datetime.fromtimestamp(file_info["modified"]).isoformat(),
                        ]
                    )

    def _export_to_xml(self, data: Dict[str, Any], file_path: Path):
        """Export data to XML format"""
        import xml.etree.ElementTree as ET

        root = ET.Element("leegion_export")
        root.set("timestamp", data["export_timestamp"])
        root.set("version", data["framework_version"])

        for component, component_data in data["components"].items():
            comp_elem = ET.SubElement(root, "component")
            comp_elem.set("name", component)
            comp_elem.set("description", component_data["description"])

            for file_info in component_data["files"]:
                file_elem = ET.SubElement(comp_elem, "file")
                file_elem.set("path", file_info["path"])
                file_elem.set("size", str(file_info["size"]))
                file_elem.set(
                    "modified",
                    datetime.fromtimestamp(file_info["modified"]).isoformat(),
                )

        tree = ET.ElementTree(root)
        tree.write(file_path, encoding="utf-8", xml_declaration=True)


# Global backup manager instance
backup_manager: Optional[BackupManager] = None


def initialize_backup_manager(config: Dict[str, Any]):
    """Initialize the global backup manager"""
    global backup_manager
    backup_manager = BackupManager(config)


def get_backup_manager() -> Optional[BackupManager]:
    """Get the global backup manager instance"""
    return backup_manager
