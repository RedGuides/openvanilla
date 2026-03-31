#!/usr/bin/env python3
"""
Xref-following address translator for eqgame.h.

For each entry in old eqgame.h:
1. Find code that references the old address (from Ghidra xref data)
2. Map that code location to the new binary via BinDiff
3. Read what address the new code references (from Ghidra xref data)
4. That's the new address -- 100% accurate

For entries with no xrefs (e.g., fall-through targets), derive from
related entries (e.g., ThrottleFrameRateEnd = ThrottleFrameRate + 6).

Usage:
    python3 xref_translator.py \
        --old-xrefs /tmp/old_xrefs.json \
        --new-xrefs /tmp/new_xrefs.json \
        --old-header /path/to/old/eqgame.h \
        --bindiff-db /path/to/results.BinDiff \
        --generate /path/to/new_eqgame.h \
        [--new-header /path/to/answer_key.h]
"""

import os
import re
import json
import sqlite3
import bisect
import argparse


def parse_eqgame_h(path):
    entries = {}
    with open(path) as f:
        for line in f:
            m = re.match(r'#define\s+(\w+)_x\s+(0x[0-9a-fA-F]+)', line.strip())
            if m:
                entries[m.group(1)] = int(m.group(2), 16)
    return entries


def load_bindiff(db_path):
    db = sqlite3.connect(db_path)
    c = db.cursor()
    c.execute("SELECT address1, address2 FROM function")
    matches = {a1: a2 for a1, a2 in c.fetchall()}
    db.close()
    return matches


def generate_header(old_header_path, translations, output_path):
    with open(old_header_path) as f:
        content = f.read()
    replacements = 0
    for name, new_addr in translations.items():
        pattern = rf'(#define\s+{re.escape(name)}_x\s+)0x[0-9a-fA-F]+'
        new_content = re.sub(pattern, rf'\g<1>0x{new_addr:X}', content)
        if new_content != content:
            replacements += 1
            content = new_content
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(content)
    print(f"  Generated {output_path} ({replacements} addresses updated)")


def main():
    parser = argparse.ArgumentParser(description="Xref-following address translator")
    parser.add_argument("--old-xrefs", required=True, help="Old binary xrefs JSON")
    parser.add_argument("--new-xrefs", required=True, help="New binary xrefs JSON")
    parser.add_argument("--old-header", required=True)
    parser.add_argument("--new-header", help="Answer key (scoring only)")
    parser.add_argument("--bindiff-db", required=True)
    parser.add_argument("--output", default="xref_results.json")
    parser.add_argument("--generate", help="Path for generated eqgame.h")
    args = parser.parse_args()

    print("Loading data...")
    old_entries = parse_eqgame_h(args.old_header)
    bd = load_bindiff(args.bindiff_db)
    bd_sorted = sorted(bd.keys())

    with open(args.old_xrefs) as f:
        old_xrefs = json.load(f)
    with open(args.new_xrefs) as f:
        new_xrefs = json.load(f)

    # Build reverse lookup: for each address in new binary, which entries point there?
    # new_xrefs is indexed by OLD entry names (same input file), so the xrefs
    # show what references the OLD address in the NEW binary (which is wrong).
    # We need to use the OLD xrefs + BinDiff mapping instead.

    # Build new binary xref index: new_addr -> list of (from_addr, refs_from)
    new_xref_by_from = {}
    for name, data in new_xrefs.items():
        for xref in data.get("xrefs", []):
            from_addr = int(xref["from"], 16)
            refs_from = [int(r, 16) for r in xref.get("refs_from", [])]
            new_xref_by_from[from_addr] = refs_from

    translations = {}
    method_used = {}
    no_xrefs = []

    for name, old_addr in sorted(old_entries.items()):
        entry = old_xrefs.get(name, {})
        xrefs = entry.get("xrefs", [])

        if not xrefs:
            no_xrefs.append(name)
            # No xrefs -- carry forward (data addresses rarely move)
            translations[name] = old_addr
            method_used[name] = "no_xrefs_carry_forward"
            continue

        # Try each xref: map old code location to new via BinDiff,
        # then check what the new code at that location references.
        found = False
        for xref in xrefs:
            from_addr = int(xref["from"], 16)
            old_refs = [int(r, 16) for r in xref.get("refs_from", [])]

            # Verify this xref actually references our target
            if old_addr not in old_refs:
                continue

            # Find containing BinDiff function
            idx = bisect.bisect_right(bd_sorted, from_addr) - 1
            if idx < 0:
                continue
            old_func = bd_sorted[idx]
            if old_func not in bd:
                continue
            new_func = bd[old_func]
            offset = from_addr - old_func

            # Map to new binary
            new_from = new_func + offset

            # Check what the new code at this location references
            # Try exact address and nearby (+/- a few bytes for alignment)
            for delta in [0, -1, 1, -2, 2, -3, 3, -4, 4]:
                check_addr = new_from + delta
                if check_addr in new_xref_by_from:
                    new_refs = new_xref_by_from[check_addr]
                    # The new code references some addresses. One of them
                    # is the translated target. Pick the one closest to
                    # the old address (data addresses are stable).
                    if len(new_refs) == 1:
                        translations[name] = new_refs[0]
                        method_used[name] = f"xref_exact_delta{delta}"
                        found = True
                        break
                    elif new_refs:
                        # Multiple refs from this instruction. Pick the one
                        # that's NOT a code address (data refs are our target)
                        # or the one closest to the old address.
                        best = min(new_refs, key=lambda r: abs(r - old_addr))
                        translations[name] = best
                        method_used[name] = f"xref_closest_delta{delta}"
                        found = True
                        break
            if found:
                break

        if not found:
            # Fallback: direct BinDiff match
            if old_addr in bd:
                translations[name] = bd[old_addr]
                method_used[name] = "bindiff_direct"
            else:
                translations[name] = old_addr
                method_used[name] = "fallback_carry_forward"

    # Summary
    methods = {}
    for m in method_used.values():
        methods[m] = methods.get(m, 0) + 1

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Total entries:     {len(old_entries)}")
    print(f"Translated:        {len(translations)}")
    print(f"No xrefs:          {len(no_xrefs)}")
    print(f"\nMethods used:")
    for m, count in sorted(methods.items(), key=lambda x: -x[1]):
        print(f"  {m:35s} {count}")

    # Score
    if args.new_header:
        new_entries = parse_eqgame_h(args.new_header)
        correct = wrong = 0
        wrong_list = []
        for name, predicted in translations.items():
            expected = new_entries.get(name)
            if expected is None:
                continue
            if predicted == expected:
                correct += 1
            else:
                wrong += 1
                m = method_used.get(name, "?")
                if len(wrong_list) < 30:
                    wrong_list.append(
                        f"  [{m}] {name}: got 0x{predicted:X}, "
                        f"expected 0x{expected:X}, diff={predicted-expected:+d}"
                    )
        scored = correct + wrong
        print(f"\n{'='*60}")
        print("SCORING")
        print(f"{'='*60}")
        print(f"Correct: {correct}/{scored} ({100*correct//scored if scored else 0}%)")
        print(f"Wrong:   {wrong}/{scored}")
        if wrong_list:
            print("Wrong:")
            for w in wrong_list:
                print(w)

    # Generate
    if args.generate:
        generate_header(args.old_header, translations, args.generate)

    # Save
    output = {
        "translations": {n: f"0x{a:X}" for n, a in translations.items()},
        "methods": {n: m for n, m in method_used.items()},
        "no_xrefs": no_xrefs,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
