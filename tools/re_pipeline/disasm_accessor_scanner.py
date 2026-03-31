#!/usr/bin/env python3
"""
disasm_accessor_scanner.py - Extract struct member accesses from disassembly.

Uses rizin disassembly (not decompiler) to find every instruction that
reads or writes to [this + offset]. This is more reliable than the
decompiler because there's no pattern-matching ambiguity.

For each function in eqgame.h:
1. Disassemble with rizin
2. Find all [reg + offset] patterns where reg holds arg1 (this pointer)
3. Classify: single-access = HIGH, write-with-arg2 = HIGH, multi = MED
4. Cross-reference with ground truth to name the offsets

Usage:
    python3 disasm_accessor_scanner.py --binary /path/to/eqgame.exe \
        --offsets /path/to/eqgame.h --struct-range 0x030:0x268
"""

import re
import os
import sys
import subprocess
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB


def disassemble_function(binary_path, addr_hex, func_name):
    """Disassemble a function and return raw text."""
    try:
        result = subprocess.run(
            ["rizin", "-a", "x86", "-b", "64", "-q",
             "-c", f"af @ {addr_hex}; pdf @ {addr_hex}",
             binary_path],
            capture_output=True, text=True, timeout=30
        )
        # Strip ANSI codes
        text = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
        return (func_name, addr_hex, text)
    except Exception:
        return (func_name, addr_hex, None)


def extract_this_offsets(disasm_text, struct_lo=0x030, struct_hi=0x268):
    """Extract all [this + offset] accesses from disassembly.

    Returns list of (offset, access_type, instruction)
    where access_type is 'read' or 'write'.

    Tracks register aliases: if rcx (arg1) is moved to rbx/rdi/rsi,
    accesses via those registers also count.
    """
    if not disasm_text:
        return []

    results = []
    lines = disasm_text.split('\n')

    # Track which registers hold 'this' (arg1 = rcx on Windows x64)
    this_regs = {'rcx'}

    # Pattern: mov reg, rcx (or other this_reg) at function start = alias
    alias_pat = re.compile(r'mov\s+(r\w+),\s*(r\w+)')

    # Pattern: access [reg + offset]
    access_pat = re.compile(
        r'(mov|movzx|movsx|lea|cmp|test|add|sub|or|and|xor)\s+'
        r'([^,]+),\s*'  # destination
        r'.*?\[(\w+)\s*\+\s*0x([0-9a-fA-F]+)\]'  # [reg + offset]
    )
    # Also: write pattern [reg + offset], src
    write_pat = re.compile(
        r'(mov|movzx)\s+'
        r'.*?\[(\w+)\s*\+\s*0x([0-9a-fA-F]+)\]'  # [reg + offset] as dest
        r',\s*(\w+)'  # source register
    )

    for line in lines:
        line = line.strip()

        # Track register aliases (first few instructions usually set up this)
        am = alias_pat.search(line)
        if am:
            dst, src = am.group(1), am.group(2)
            if src in this_regs:
                this_regs.add(dst)

        # Check for writes: mov [reg+off], something
        wm = write_pat.search(line)
        if wm:
            reg = wm.group(2)
            offset = int(wm.group(3), 16)
            if reg in this_regs and struct_lo <= offset < struct_hi:
                results.append((offset, 'write', line))
                continue

        # Check for reads: mov something, [reg+off]
        rm = access_pat.search(line)
        if rm:
            reg = rm.group(3)
            offset = int(rm.group(4), 16)
            if reg in this_regs and struct_lo <= offset < struct_hi:
                results.append((offset, 'read', line))

    return results


def classify_function(func_name, accesses):
    """Classify a function's relationship to struct offsets.

    Returns list of (offset, confidence, evidence_type, detail)
    """
    if not accesses:
        return []

    # Unique offsets accessed
    offsets = defaultdict(lambda: {'reads': [], 'writes': []})
    for offset, atype, instr in accesses:
        offsets[offset][atype + 's'].append(instr)

    results = []
    unique_offsets = set(offsets.keys())

    # Single-offset function: definitive identifier
    if len(unique_offsets) == 1:
        off = list(unique_offsets)[0]
        writes = offsets[off]['writes']
        reads = offsets[off]['reads']
        if writes:
            results.append((off, 'HIGH', 'setter',
                           f"only offset in {func_name}, writes"))
        else:
            results.append((off, 'HIGH', 'getter',
                           f"only offset in {func_name}, reads"))
        return results

    # Two-offset function where one is a write: strong setter candidate
    if len(unique_offsets) == 2:
        for off in unique_offsets:
            if offsets[off]['writes']:
                results.append((off, 'HIGH', 'setter',
                               f"write target in simple {func_name} (2 offsets)"))
            else:
                results.append((off, 'MED', 'access',
                               f"read in simple {func_name} (2 offsets)"))
        return results

    # Three-offset function with one write: still decent
    if len(unique_offsets) <= 4:
        for off in unique_offsets:
            if offsets[off]['writes']:
                results.append((off, 'MED', 'setter',
                               f"write in {func_name} ({len(unique_offsets)} offsets)"))
            else:
                results.append((off, 'MED', 'access',
                               f"read in {func_name} ({len(unique_offsets)} offsets)"))
        return results

    # Complex function: all accesses are LOW, but still useful for coverage
    for off in unique_offsets:
        results.append((off, 'LOW', 'access',
                       f"access in complex {func_name} ({len(unique_offsets)} offsets)"))

    return results


def scan_binary(binary_path, offsets_path, struct_range, workers=32, cache_dir=None):
    """Scan all functions in eqgame.h against a binary."""

    struct_lo, struct_hi = struct_range

    # Parse all function addresses from eqgame.h
    functions = {}
    with open(offsets_path) as f:
        for line in f:
            m = re.match(r'#define\s+(\S+)_x\s+(0x[0-9a-fA-F]+)', line.strip())
            if m:
                functions[m.group(1)] = m.group(2)

    print(f"Scanning {len(functions)} functions in {binary_path}")

    # Disassemble all functions (with caching)
    disasm_results = {}

    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)

    to_disasm = {}
    for func_name, addr in functions.items():
        if cache_dir:
            cache_file = cache_dir / f"{func_name}.asm"
            if cache_file.exists():
                disasm_results[func_name] = (func_name, addr, cache_file.read_text())
                continue
        to_disasm[func_name] = addr

    if disasm_results:
        print(f"  {len(disasm_results)} cached, {len(to_disasm)} to disassemble")

    if to_disasm:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(disassemble_function, binary_path, addr, name): name
                for name, addr in to_disasm.items()
            }
            done = 0
            for future in as_completed(futures):
                name, addr, text = future.result()
                done += 1
                if text and len(text) > 10:
                    disasm_results[name] = (name, addr, text)
                    if cache_dir:
                        (cache_dir / f"{name}.asm").write_text(text)
                if done % 50 == 0:
                    print(f"  Disassembled {done}/{len(to_disasm)}...")

    print(f"  Total disassembled: {len(disasm_results)}")

    # Extract offset accesses from each function
    all_classifications = []  # (func_name, offset, confidence, evidence_type, detail)

    for func_name, (_, addr, text) in disasm_results.items():
        accesses = extract_this_offsets(text, struct_lo, struct_hi)
        classifications = classify_function(func_name, accesses)
        for offset, confidence, etype, detail in classifications:
            all_classifications.append((func_name, int(addr, 16), offset, confidence, etype, detail))

    return all_classifications


def populate_db(db, binary_id, classifications, struct_class='CXWnd'):
    """Store scan results in the database."""
    count = 0
    for func_name, func_addr, offset, confidence, etype, detail in classifications:
        # Look up which field is at this offset in this build
        member = db.get_member_at_offset(binary_id, struct_class, offset)
        if not member:
            # Try CSidlScreenWnd
            member = db.get_member_at_offset(binary_id, 'CSidlScreenWnd', offset)
            if member:
                struct_class_actual = 'CSidlScreenWnd'
            else:
                continue
        else:
            struct_class_actual = struct_class

        field_name = member['field_name']

        db.add_evidence(
            binary_id=binary_id,
            class_name=struct_class_actual,
            field_name=field_name,
            func_name=func_name,
            func_addr=func_addr,
            evidence_type=etype,
            decompile_line=detail,
            confidence=confidence
        )
        count += 1

    return count


def main():
    parser = argparse.ArgumentParser(description="Disassembly-based accessor scanner")
    parser.add_argument("--build", help="Specific build date (scans one)")
    parser.add_argument("--all", action="store_true", help="Scan all builds")
    parser.add_argument("--binary", help="Path to eqgame.exe (if not using --build)")
    parser.add_argument("--offsets", help="Path to eqgame.h (if not using --build)")
    parser.add_argument("--struct-range", default="0x030:0x268",
                        help="Offset range lo:hi (default CXWnd)")
    parser.add_argument("--workers", type=int, default=32, help="Parallel workers")
    parser.add_argument("--no-db", action="store_true", help="Don't write to database")
    args = parser.parse_args()

    lo, hi = [int(x, 16) for x in args.struct_range.split(':')]

    db = EQXrefDB()

    if args.all:
        builds = [(r['build_date'], r['binary_path'], r['eqgame_h'])
                  for r in db.list_binaries() if r['server'] == 'live' and r['eqgame_h']]
    elif args.build:
        bid = db.get_binary_id(args.build)
        row = db.conn.execute("SELECT * FROM binaries WHERE id = ?", (bid,)).fetchone()
        builds = [(row['build_date'], row['binary_path'], row['eqgame_h'])]
    elif args.binary and args.offsets:
        builds = [('standalone', args.binary, args.offsets)]
    else:
        print("Specify --build DATE, --all, or --binary + --offsets")
        return

    for build_date, binary_path, offsets_path in sorted(builds):
        print(f"\n{'='*60}")
        print(f"Build: {build_date}")
        print(f"{'='*60}")

        cache = os.path.join(os.path.dirname(__file__), '..', '..', 'data',
                            'disasm_cache', build_date)

        classifications = scan_binary(binary_path, offsets_path,
                                      (lo, hi), args.workers, cache)

        # Stats
        high = sum(1 for c in classifications if c[3] == 'HIGH')
        med = sum(1 for c in classifications if c[3] == 'MED')
        low = sum(1 for c in classifications if c[3] == 'LOW')
        unique_offsets = len(set(c[2] for c in classifications))

        print(f"\n  Results: {len(classifications)} total accesses")
        print(f"  HIGH: {high}, MED: {med}, LOW: {low}")
        print(f"  Unique offsets covered: {unique_offsets}")

        # Show HIGH confidence findings
        print(f"\n  HIGH confidence identifications:")
        for fn, fa, off, conf, etype, detail in sorted(classifications, key=lambda x: x[2]):
            if conf == 'HIGH':
                print(f"    0x{off:03x}  {etype:6s}  {fn}")

        if not args.no_db and build_date != 'standalone':
            bid = db.get_binary_id(build_date)
            if bid:
                # Clear old evidence for this build, but preserve gap_analysis records
                db.conn.execute("""
                    DELETE FROM evidence_records
                    WHERE binary_id = ?
                      AND id NOT IN (
                          SELECT er.id FROM evidence_records er
                          JOIN function_identities fi ON er.func_id = fi.id
                          WHERE er.binary_id = ? AND fi.func_name = 'gap_analysis'
                      )
                """, (bid, bid))
                db.conn.commit()
                count = populate_db(db, bid, classifications)
                print(f"\n  Stored {count} evidence records in database")

    if not args.no_db:
        print(f"\nFinal database stats:")
        for k, v in db.stats().items():
            print(f"  {k}: {v}")

    db.close()


if __name__ == '__main__':
    main()
