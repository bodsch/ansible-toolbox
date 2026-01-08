#!/usr/bin/python

import os
import re
import sys
import time
import yaml
import argparse
import requests
from pathlib import Path
from collections import defaultdict

# --- Konfiguration ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
USES_REGEX = re.compile(r'(?P<action>[^\s:@]+\/[^\s:@]+)@(?P<version>[^\s\n\'"]+)')

RATE_LIMIT_REMAINING_HEADER = "X-RateLimit-Remaining"
RATE_LIMIT_RESET_HEADER = "X-RateLimit-Reset"

# --- Funktionen ---
def find_workflow_files(root_path="."):
    return list(Path(root_path).rglob(".github/workflows/*.y*ml"))

def normalize_tag(tag):
    """v4.2.2 → v4"""
    return re.match(r"v\d+", tag).group(0) if tag.startswith("v") else tag

def extract_uses_entries(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return [(m.group("action"), m.group("version")) for m in USES_REGEX.finditer(content)]

def check_rate_limit(response):
    remaining = int(response.headers.get(RATE_LIMIT_REMAINING_HEADER, 1))
    if remaining <= 1:
        reset_time = int(response.headers.get(RATE_LIMIT_RESET_HEADER, time.time() + 60))
        wait_seconds = max(reset_time - int(time.time()), 1)
        print(f"⏳ Rate limit reached. Sleeping for {wait_seconds} seconds...")
        time.sleep(wait_seconds)

def get_latest_version(repo, verbose=False):
    # try /releases/latest first
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    r = requests.get(url, headers=HEADERS)
    check_rate_limit(r)
    if r.status_code == 200:
        return r.json()["tag_name"]

    # fallback to tags
    url = f"https://api.github.com/repos/{repo}/tags"
    r = requests.get(url, headers=HEADERS)
    check_rate_limit(r)
    if r.status_code == 200 and r.json():
        return r.json()[0]["name"]
    if verbose:
        print(f"⚠️  Could not find version info for {repo}")
    return None

def update_workflow_file(file_path, updates, dry_run=False):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    original = content

    for action, (old, new) in updates.items():
        # pattern = re.compile(rf'({re.escape(action)}@){re.escape(old)}')
        # content = pattern.sub(rf'\1{new}', content)
        pattern = re.compile(
            rf'(?<![\w/-])({re.escape(action)}@){re.escape(old)}(?=[\s\n\'"])'
        )
        content = pattern.sub(rf'\1{new}', content)


    if content != original:
        if dry_run:
            print(f"[DRY-RUN] Would update: {file_path}")
        else:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"✅ Updated: {file_path}")

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="🔧 GitHub Actions Updater")
    parser.add_argument("--dry-run", action="store_true", help="Nur anzeigen, keine Dateien ändern")
    parser.add_argument("--verbose", action="store_true", help="Mehr Details ausgeben")
    parser.add_argument("--root", default=".", help="Wurzelverzeichnis des Repos")

    args = parser.parse_args()
    dry_run = args.dry_run
    verbose = args.verbose

    print("🔍 Scanning for workflow files...")
    workflows = find_workflow_files(args.root)
    uses_map = defaultdict(set)

    for wf in workflows:
        for action, version in extract_uses_entries(wf):
            uses_map[action].add(version)

    if verbose:
        print("📦 Gefundene Actions:")
        for action, versions in uses_map.items():
            print(f"  - {action}: {', '.join(versions)}")

    updates = {}
    for action in sorted(uses_map):
        if action.startswith("./"):
            continue  # lokale Actions überspringen

        latest = get_latest_version(action, verbose=verbose)
        if not latest:
            continue

        for current_version in uses_map[action]:
            # if current_version != latest and not current_version.startswith("sha256-"):
            if (
                current_version != latest
                and not current_version.startswith("sha256-")
                and normalize_tag(current_version) != normalize_tag(latest)
            ):

            # if (current_version != latest
            #     and not current_version.startswith("sha256-")
            #     and normalize_tag(current_version) != normalize_tag(latest)):
                """ """
                if verbose:
                    print(f"🔁 {action}@{current_version} → @{latest}")
                updates[action] = (current_version, latest)

    if not updates:
        print("✅ Alle Actions sind aktuell.")
        return

    print(f"🔧 Änderungen werden {'simuliert' if dry_run else 'ausgeführt'}...")

    for wf in workflows:
        update_workflow_file(wf, updates, dry_run=dry_run)

    print("🏁 Fertig.")

if __name__ == "__main__":
    main()
