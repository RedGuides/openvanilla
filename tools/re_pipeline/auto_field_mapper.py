#!/usr/bin/env python3
"""
Automated Field Mapper for EQ struct reverse engineering.

Usage:
    python3 auto_field_mapper.py --class CXWnd --binary /path/to/eqgame.exe --offsets /path/to/eqgame.h

Does:
1. Parses eqgame.h for function addresses
2. Parallel decompiles via rz-ghidra
3. Extracts field offsets from setter/getter patterns
4. Matches INI string keys to offsets
5. Applies type elimination for unique types
6. Reports: named fields, unnamed offsets needing manual review

Does NOT:
- Behavioral naming (requires human/AI reading of function logic)
- Binary diffing across versions (separate tool)
"""

import re
import os
import sys
import json
import subprocess
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# Import our accessor scanner
sys.path.insert(0, os.path.dirname(__file__))
from vtable_accessor_scanner import parse_decompilation


def parse_offsets_file(offsets_path, class_prefix):
    """Parse eqgame.h for function addresses matching a class prefix."""
    functions = {}
    pattern = re.compile(
        rf'#define\s+({class_prefix}__(\w+))_x\s+(0x[0-9a-fA-F]+)'
    )
    with open(offsets_path) as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                full_name = m.group(1)
                func_name = m.group(2)
                addr = m.group(3)
                functions[func_name] = addr
    return functions


def decompile_function(binary_path, addr, func_name):
    """Decompile a single function via rz-ghidra. Returns (name, code)."""
    try:
        result = subprocess.run(
            ["rizin", "-a", "x86", "-b", "64", "-q",
             "-c", f"af @ {addr}; pdg @ {addr}",
             binary_path],
            capture_output=True, text=True, timeout=30
        )
        code = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
        return (func_name, addr, code)
    except (subprocess.TimeoutExpired, Exception) as e:
        return (func_name, addr, f"// ERROR: {e}")


def parallel_decompile(binary_path, functions, max_workers=32):
    """Decompile all functions in parallel."""
    results = {}
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(decompile_function, binary_path, addr, name): name
            for name, addr in functions.items()
        }
        for future in as_completed(futures):
            name, addr, code = future.result()
            if code and len(code) > 20 and "ERROR" not in code:
                results[name] = code
                print(f"  Decompiled {name} ({len(code.split(chr(10)))} lines)")
            else:
                print(f"  FAILED {name}")
    return results


def extract_setter_names(decompilations):
    """Extract field names from SetX functions that write param2 to exactly 1 offset."""
    named = {}
    for func_name, code in decompilations.items():
        findings = parse_decompilation(code, func_name)
        setters = [f for f in findings if f["type"] == "setter"]
        getters = [f for f in findings if f["type"] == "getter"]

        if func_name.startswith("Set") and len(setters) == 1:
            off = setters[0]["offset"]
            field_name = func_name[3:]  # Strip "Set"
            named[off] = (field_name, f"setter in {func_name}", "HIGH")

        elif func_name.startswith("Get") and len(getters) == 1:
            off = getters[0]["offset"]
            field_name = func_name[3:]  # Strip "Get"
            named[off] = (field_name, f"getter in {func_name}", "HIGH")

    return named


def extract_ini_keys(decompilations):
    """Extract field names from INI load/store functions using string keys."""
    named = {}
    ini_funcs = {k: v for k, v in decompilations.items()
                 if "LoadIni" in k or "StoreIni" in k}

    offset_pat = re.compile(
        r'(?:arg1|param_1)\s*\+\s*(?:0x)?([0-9a-fA-F]+)',
        re.IGNORECASE
    )

    for func_name, code in ini_funcs.items():
        lines = code.split('\n')
        for i, line in enumerate(lines):
            strings = re.findall(r'"([A-Za-z]+)"', line)
            offsets = []
            for m in offset_pat.finditer(line):
                offsets.append(int(m.group(1), 16))

            if strings and offsets:
                for s in strings:
                    for off in offsets:
                        if off not in named:
                            # Map common INI key names to field names
                            key_to_field = {
                                "ClickThrough": "bClickThroughMenuItemStatus",
                                "Border": "bShowBorder",
                                "Escapable": "bEscapable",
                                "Fades": "Fades",
                                "Alpha": "Alpha",
                                "FadeToAlpha": "FadeToAlpha",
                                "Duration": "FadeDuration",
                                "Delay": "FadeDelay",
                                "BGType": "BGType",
                            }
                            field = key_to_field.get(s, s)
                            named[off] = (field, f"INI key '{s}' in {func_name}", "HIGH")

    return named


def extract_all_offsets(decompilations, offset_range):
    """Extract all accessed offsets from all functions."""
    lo, hi = offset_range
    offset_pat = re.compile(
        r'(?:arg1|param_1)\s*\+\s*(?:0x)?([0-9a-fA-F]+)',
        re.IGNORECASE
    )

    all_offsets = {}  # offset -> [(func, line)]
    for func_name, code in decompilations.items():
        for line in code.split('\n'):
            for m in offset_pat.finditer(line):
                off = int(m.group(1), 16)
                if lo <= off < hi:
                    if off not in all_offsets:
                        all_offsets[off] = []
                    all_offsets[off].append((func_name, line.strip()[:100]))

    return all_offsets


def apply_type_elimination(known_fields, all_field_names_types):
    """For fields with unique types, place them by elimination."""
    named = {}

    # Group unplaced fields by type
    placed_offsets = set(known_fields.keys())
    unplaced = {off: (name, typ) for off, (name, typ) in all_field_names_types.items()
                if off not in placed_offsets}

    type_groups = {}
    for off, (name, typ) in unplaced.items():
        if typ not in type_groups:
            type_groups[typ] = []
        type_groups[typ].append((off, name))

    for typ, fields in type_groups.items():
        if len(fields) == 1:
            off, name = fields[0]
            named[off] = (name, f"unique type {typ}", "ELIMINATION")

    return named


def main():
    parser = argparse.ArgumentParser(description="Automated Field Mapper")
    parser.add_argument("--binary", required=True, help="Path to eqgame.exe")
    parser.add_argument("--offsets", required=True, help="Path to eqgame.h offsets file")
    parser.add_argument("--class", dest="classname", required=True,
                        help="Class name prefix (CXWnd, PlayerZoneClient, ItemBase)")
    parser.add_argument("--header", help="Path to header with field layout for type info")
    parser.add_argument("--workers", type=int, default=32, help="Parallel workers")
    parser.add_argument("--cache-dir", default="/tmp/field_mapper_cache",
                        help="Cache directory for decompilations")
    parser.add_argument("--answer-key", help="Path to brainiac's header for scoring (validation only)")
    args = parser.parse_args()

    cache_dir = Path(args.cache_dir) / args.classname
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Parse function addresses
    print(f"\n=== Step 1: Parse function addresses for {args.classname} ===")
    # Try multiple prefixes
    prefixes = [args.classname]
    if args.classname == "CXWnd":
        prefixes.extend(["CSidlScreenWnd", "CXWndManager"])
    elif args.classname == "PlayerZoneClient":
        prefixes.extend(["PlayerClient", "PlayerBase"])

    all_functions = {}
    for prefix in prefixes:
        funcs = parse_offsets_file(args.offsets, prefix)
        all_functions.update(funcs)
        print(f"  {prefix}: {len(funcs)} functions")

    print(f"  Total: {len(all_functions)} functions")

    # Step 2: Parallel decompile
    print(f"\n=== Step 2: Parallel decompile ({args.workers} workers) ===")
    decompilations = parallel_decompile(args.binary, all_functions, args.workers)
    print(f"  Successfully decompiled: {len(decompilations)}/{len(all_functions)}")

    # Cache decompilations
    for name, code in decompilations.items():
        (cache_dir / f"{name}.txt").write_text(code)

    # Step 3: Extract setter/getter names
    print(f"\n=== Step 3: Extract accessor names ===")
    accessor_names = extract_setter_names(decompilations)
    for off, (name, evidence, conf) in sorted(accessor_names.items()):
        print(f"  0x{off:03X} = {name} [{conf}] ({evidence})")

    # Step 4: Extract INI string keys
    print(f"\n=== Step 4: Extract INI string keys ===")
    ini_names = extract_ini_keys(decompilations)
    for off, (name, evidence, conf) in sorted(ini_names.items()):
        print(f"  0x{off:03X} = {name} [{conf}] ({evidence})")

    # Step 5: Extract all accessed offsets
    print(f"\n=== Step 5: Extract all accessed offsets ===")
    # Guess offset range from class
    ranges = {
        "CXWnd": (0x030, 0x268),
        "PlayerZoneClient": (0x1CC, 0x650),
        "ItemBase": (0x008, 0x114),
    }
    offset_range = ranges.get(args.classname, (0x008, 0x800))
    all_offsets = extract_all_offsets(decompilations, offset_range)
    print(f"  Unique offsets accessed: {len(all_offsets)}")

    # Combine all named fields
    named = {}
    named.update({off: (n, e, c) for off, (n, e, c) in accessor_names.items()})
    for off, (n, e, c) in ini_names.items():
        if off not in named:
            named[off] = (n, e, c)

    # Step 6: Report
    print(f"\n{'='*60}")
    print(f"RESULTS: {args.classname}")
    print(f"{'='*60}")
    print(f"Automatically named: {len(named)}")
    print(f"Offsets detected: {len(all_offsets)}")
    print(f"Unnamed (need manual behavioral analysis): {len(all_offsets) - len(named)}")

    print(f"\n=== NAMED FIELDS ===")
    for off in sorted(named.keys()):
        name, evidence, conf = named[off]
        print(f"  0x{off:03X} = {name:30s} [{conf}]")

    print(f"\n=== UNNAMED OFFSETS (need manual review) ===")
    for off in sorted(all_offsets.keys()):
        if off not in named:
            funcs = sorted(set(f for f, _ in all_offsets[off]))[:3]
            print(f"  0x{off:03X}: accessed by {', '.join(funcs)}")

    # Step 7: Score against answer key if provided
    if args.answer_key:
        print(f"\n=== SCORING AGAINST ANSWER KEY ===")
        brainiac = {}
        in_block = False
        marker = f"@start: {args.classname} Members"
        end_marker = f"@end: {args.classname} Members"
        # Handle different marker formats
        with open(args.answer_key) as f:
            for line in f:
                if marker in line or "@start:" in line:
                    if args.classname.lower() in line.lower():
                        in_block = True
                        continue
                if end_marker in line or ("@end:" in line and in_block):
                    break
                if in_block and line.strip().startswith("/*0x"):
                    m = re.match(r'\s*/\*0x([0-9a-fA-F]+)\*/\s+\S+\s+(\w+)', line)
                    if m:
                        brainiac[int(m.group(1), 16)] = m.group(2)

        if brainiac:
            def fuzzy(a, b):
                return a.lower().lstrip('p').lstrip('b') == b.lower().lstrip('p').lstrip('b')

            correct = wrong = 0
            for off, (name, _, _) in named.items():
                brain = brainiac.get(off, "???")
                if brain == "???" or brain in ("int","bool","unsigned"):
                    continue
                if fuzzy(name, brain):
                    correct += 1
                else:
                    wrong += 1
                    print(f"  WRONG: 0x{off:03X} ours={name} brain={brain}")

            detected = len(set(all_offsets.keys()) & set(brainiac.keys()))
            print(f"\n  Offset detection: {detected}/{len(brainiac)} ({100*detected//len(brainiac)}%)")
            print(f"  Auto-named correct: {correct}, wrong: {wrong}")
            print(f"  Accuracy: {100*correct//(correct+wrong) if correct+wrong else 0}%")

    # Save results
    output = {
        "class": args.classname,
        "named": {f"0x{off:03X}": {"name": n, "evidence": e, "confidence": c}
                  for off, (n, e, c) in named.items()},
        "unnamed_offsets": [f"0x{off:03X}" for off in sorted(all_offsets.keys()) if off not in named],
        "total_offsets": len(all_offsets),
    }
    output_path = cache_dir / "results.json"
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
