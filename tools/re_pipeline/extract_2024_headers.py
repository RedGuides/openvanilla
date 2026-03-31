#!/usr/bin/env python3
"""
extract_2024_headers.py - Extract eqgame.h ground truth for 2024 builds from eqlib git history.

Walks the eqlib-history repo's live branch, finds commits whose __ClientDate
matches our 2024 build dates, and extracts eqgame.h + CXWnd.h to the build dirs.
Also registers the builds in the xref database.
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

EQLIB_REPO = os.path.join(os.path.dirname(__file__), '..', '..', 'eqlib-history')
BUILDS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'eq-builds', 'live')


def get_all_clientdates():
    """Get all commits on live branch with their __ClientDate values."""
    # Get all commits on live branch
    result = subprocess.run(
        ['git', '-C', EQLIB_REPO, 'log', 'live', '--oneline', '--format=%H'],
        capture_output=True, text=True)
    commits = result.stdout.strip().split('\n')

    date_to_commit = {}
    for commit in commits:
        if not commit:
            continue
        # Get __ClientDate from eqgame.h at this commit
        # Try both old path (root) and new path (include/eqlib/offsets/)
        for path in ['eqgame.h', 'include/eqlib/offsets/eqgame.h']:
            try:
                result = subprocess.run(
                    ['git', '-C', EQLIB_REPO, 'show', f'{commit}:{path}'],
                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    m = re.search(r'__ClientDate\s+(\d+)', result.stdout)
                    if m:
                        cdate = m.group(1).rstrip('u')
                        # Convert YYYYMMDD to YYYY-MM-DD
                        if len(cdate) == 8:
                            formatted = f"{cdate[:4]}-{cdate[4:6]}-{cdate[6:8]}"
                            date_to_commit[formatted] = (commit, path)
                    break
            except:
                continue

    return date_to_commit


def extract_header(commit, path, output_path):
    """Extract a file from git at a specific commit."""
    result = subprocess.run(
        ['git', '-C', EQLIB_REPO, 'show', f'{commit}:{path}'],
        capture_output=True, text=True)
    if result.returncode == 0:
        with open(output_path, 'w') as f:
            f.write(result.stdout)
        return True
    return False


def main():
    db = EQXrefDB()

    # Get our 2024 build directories
    build_dirs = sorted([d for d in os.listdir(BUILDS_DIR) if d.startswith('2024-')])
    print(f"Found {len(build_dirs)} build directories from 2024")

    # Get clientdate→commit mapping from git
    print("Scanning eqlib git history for ClientDates...")
    date_to_commit = get_all_clientdates()
    print(f"Found {len(date_to_commit)} unique ClientDates in git")

    matched = 0
    unmatched = []

    for build_date in build_dirs:
        build_dir = os.path.join(BUILDS_DIR, build_date)
        exe_path = os.path.join(build_dir, 'eqgame.exe')
        h_path = os.path.join(build_dir, 'eqgame.h')

        if not os.path.exists(exe_path):
            print(f"  {build_date}: no eqgame.exe, skipping")
            continue

        if os.path.exists(h_path):
            print(f"  {build_date}: eqgame.h already exists")
            matched += 1
            # Still register in DB if not there
            bid = db.get_binary_id(build_date)
            if not bid:
                bid = db.add_binary(build_date, exe_path, h_path)
                count = db.ingest_eqgame_h(bid, h_path)
                print(f"    Registered in DB: {count} functions")
            continue

        # Try to match this build date to a git ClientDate
        if build_date in date_to_commit:
            commit, git_path = date_to_commit[build_date]
            print(f"  {build_date}: exact match → commit {commit[:8]}")
        else:
            # Try nearby dates (build date might be 1-2 days off from ClientDate)
            found = False
            year, month, day = build_date.split('-')
            from datetime import date, timedelta
            base_date = date(int(year), int(month), int(day))
            for delta in range(-3, 4):
                check = base_date + timedelta(days=delta)
                check_str = check.strftime('%Y-%m-%d')
                if check_str in date_to_commit:
                    commit, git_path = date_to_commit[check_str]
                    print(f"  {build_date}: matched to ClientDate {check_str} → commit {commit[:8]}")
                    found = True
                    break
            if not found:
                unmatched.append(build_date)
                print(f"  {build_date}: NO MATCH in git history")
                continue

        # Extract eqgame.h
        if extract_header(commit, git_path, h_path):
            print(f"    Extracted eqgame.h ({os.path.getsize(h_path)} bytes)")
            matched += 1

            # Also try CXWnd.h
            for cxwnd_path in ['CXWnd.h', 'include/eqlib/game/CXWnd.h']:
                cxwnd_out = os.path.join(build_dir, 'CXWnd.h')
                if extract_header(commit, cxwnd_path, cxwnd_out):
                    print(f"    Extracted CXWnd.h")
                    break

            # Register in database
            bid = db.get_binary_id(build_date)
            if not bid:
                bid = db.add_binary(build_date, exe_path, h_path)
            else:
                # Update eqgame_h path
                db.conn.execute("UPDATE binaries SET eqgame_h = ? WHERE id = ?", (h_path, bid))
                db.conn.commit()

            count = db.ingest_eqgame_h(bid, h_path)
            print(f"    Ingested {count} functions into DB")

            # Ingest CXWnd.h member offsets if available
            cxwnd_file = os.path.join(build_dir, 'CXWnd.h')
            if os.path.exists(cxwnd_file):
                mcount = db.ingest_struct_header(bid, cxwnd_file, 'CXWnd',
                                                  start_marker='// @start: CXWnd Members',
                                                  end_marker='// @end: CXWnd Members')
                if mcount > 0:
                    print(f"    Ingested {mcount} CXWnd member offsets")

    print(f"\n{'='*60}")
    print(f"Matched: {matched}/{len(build_dirs)}")
    if unmatched:
        print(f"Unmatched ({len(unmatched)}): {', '.join(unmatched)}")

    print(f"\nDB stats:")
    for k, v in db.stats().items():
        print(f"  {k}: {v}")

    db.close()


if __name__ == '__main__':
    main()
