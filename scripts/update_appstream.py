#!/usr/bin/env python3
"""
Update AppStream metadata with new release information.
This script adds a new release entry to the appdata.xml file.
"""

import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def update_appstream(version: str, date: str, appdata_file: Path) -> bool:
    """
    Add a new release entry to the AppStream metadata file.
    
    Args:
        version: Release version (e.g., "4.4.4")
        date: Release date in YYYY-MM-DD format
        appdata_file: Path to the appdata.xml file
    
    Returns:
        True if release was added, False if it already existed
    """
    # Parse the XML file
    tree = ET.parse(appdata_file)
    root = tree.getroot()
    
    # Find the releases element
    releases_elem = root.find("releases")
    if releases_elem is None:
        # Create releases element if it doesn't exist
        releases_elem = ET.SubElement(root, "releases")
    
    # Check if version already exists
    for release in releases_elem.findall("release"):
        if release.get("version") == version:
            print(f"✓ Release {version} already in appdata.xml")
            return False
    
    # Create new release element
    new_release = ET.Element("release")
    new_release.set("version", version)
    new_release.set("date", date)
    
    # Insert at the beginning (after any existing releases)
    releases_elem.insert(0, new_release)
    
    # Write the updated XML back to file
    tree.write(appdata_file, encoding="UTF-8", xml_declaration=True)
    
    # Reformat the XML for readability (optional but nice)
    _format_xml(appdata_file)
    
    print(f"✓ Added release {version} ({date}) to appdata.xml")
    return True


def _format_xml(file_path: Path) -> None:
    """Format XML file with proper indentation."""
    import subprocess
    
    try:
        # Use xmllint if available for pretty printing
        result = subprocess.run(
            ["xmllint", "--format", str(file_path)],
            capture_output=True,
            text=True,
            check=True
        )
        file_path.write_text(result.stdout, encoding="UTF-8")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # xmllint not available, skip formatting
        pass


def main():
    if len(sys.argv) < 3:
        print("Usage: update_appstream.py <version> <date> [appdata_file]")
        print("  version: Release version (e.g., 4.4.4)")
        print("  date: Release date in YYYY-MM-DD format")
        print("  appdata_file: Path to appdata.xml (default: org.electroncash.ElectronCash.appdata.xml)")
        sys.exit(1)
    
    version = sys.argv[1]
    date = sys.argv[2]
    appdata_file = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("org.electroncash.ElectronCash.appdata.xml")
    
    # Validate date format
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        print(f"Error: Invalid date format '{date}'. Use YYYY-MM-DD format.")
        sys.exit(1)
    
    # Validate file exists
    if not appdata_file.exists():
        print(f"Error: File not found: {appdata_file}")
        sys.exit(1)
    
    update_appstream(version, date, appdata_file)


if __name__ == "__main__":
    main()
