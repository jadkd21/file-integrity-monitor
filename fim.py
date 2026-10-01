#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Takes a fingerprint (SHA-256 hash) of every file in a folder, then later
re-checks and tells you exactly what changed: new, deleted, or modified.

This is the same idea behind real tools like Tripwire and Wazuh FIM -
attackers often modify system files, and a FIM is how defenders notice.

How to run:
    python fim.py init    -> create a baseline of a folder
    python fim.py check   -> compare the folder against the baseline
"""

import hashlib
import json
import os
import sys
from datetime import datetime

BASELINE_FILE = "baseline.json"


def sha256_of(path):
    """Fingerprint a file. Even one changed byte = totally different hash."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(folder):
    """Hash every file under folder. Returns {relative_path: hash}."""
    records = {}
    baseline_abs = os.path.abspath(BASELINE_FILE)
    for root, _dirs, files in os.walk(folder):
        for name in files:
            full = os.path.join(root, name)
            if os.path.abspath(full) == baseline_abs:
                continue  # don't fingerprint our own database
            try:
                records[os.path.relpath(full, folder)] = sha256_of(full)
            except (OSError, PermissionError):
                continue  # locked/system files we can't read
    return records


def save_baseline(records):
    with open(BASELINE_FILE, "w") as f:
        json.dump({"created": datetime.now().isoformat(),
                   "files": records}, f, indent=2)


def load_baseline():
    with open(BASELINE_FILE) as f:
        data = json.load(f)
    return data["files"], data["created"]


def ask_folder():
    folder = input("Folder to monitor (Enter = this folder): ").strip()
    if not folder:
        folder = "."
    if not os.path.isdir(folder):
        print(f"Not a folder: {folder}")
        sys.exit(1)
    return folder


def cmd_init():
    folder = ask_folder()
    records = snapshot(folder)
    save_baseline(records)
    print(f"\nBaseline saved: {len(records)} files fingerprinted.")
    print(f"Stored in {BASELINE_FILE} (created {datetime.now():%Y-%m-%d %H:%M}).")
    print("Run 'python fim.py check' later to detect changes.")


def cmd_check():
    if not os.path.exists(BASELINE_FILE):
        print("No baseline yet. Run 'python fim.py init' first.")
        sys.exit(1)
    folder = ask_folder()
    old, created = load_baseline()
    new = snapshot(folder)

    added = [p for p in new if p not in old]
    deleted = [p for p in old if p not in new]
    modified = [p for p in new if p in old and new[p] != old[p]]

    print(f"\nBaseline from: {created}")
    print(f"Files now: {len(new)} (baseline had {len(old)})")
    print("-" * 55)

    if not (added or deleted or modified):
        print("  [OK] No changes detected. Everything matches the baseline.")
        return

    for p in added:
        print(f"  [NEW]      {p}")
    for p in deleted:
        print(f"  [DELETED]  {p}")
    for p in modified:
        print(f"  [MODIFIED] {p}")

    print(f"\n  {len(added)} new, {len(deleted)} deleted, {len(modified)} modified.")
    print("  Tip: investigate unexpected changes - modified system")
    print("  files are a classic sign of an intrusion.")


def main():
    print("=" * 55)
    print("  FILE INTEGRITY MONITOR")
    print("=" * 55)
    if len(sys.argv) < 2 or sys.argv[1] not in ("init", "check"):
        print("\nUsage:")
        print("  python fim.py init   - fingerprint a folder (baseline)")
        print("  python fim.py check  - detect changes since baseline")
        sys.exit(1)
    if sys.argv[1] == "init":
        cmd_init()
    else:
        cmd_check()


if __name__ == "__main__":
    main()
