#!/usr/bin/env python3
"""
Parse batch-decompiled vtable functions and extract field access patterns.

Input: /tmp/cxwnd_all_decompiled.txt (from rz-ghidra batch)
       /tmp/cxwnd_vtable_addrs.txt (vtable index -> function address mapping)

Output: Field offset map with confidence levels.

This script does NOT reference any answer key.
"""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from vtable_accessor_scanner import parse_decompilation, type_to_size

# Known vtable function names from CXWnd::VirtualFunctionTable
# Corrected vtable-to-name mapping from CXWnd::VirtualFunctionTable struct
# Source: our own CXWnd.h VirtualFunctionTable (corrected index alignment)
VTABLE_NAMES = {
    0: "IsValid", 1: "Destructor", 2: "GetWndClassName",
    3: "DrawNC", 4: "Draw", 5: "PostDraw", 6: "DrawCursor",
    7: "DrawChildItem", 8: "DrawCaret", 9: "DrawBackground",
    10: "DrawTooltip", 11: "DrawTooltipAtPoint", 12: "GetMinimizedRect",
    13: "DrawTitleBar", 14: "SetZLayer", 15: "GetCursorToDisplay",
    16: "HandleLButtonDown", 17: "HandleLButtonUp", 18: "HandleLButtonHeld",
    19: "HandleLButtonUpAfterHeld", 20: "HandleRButtonDown",
    21: "HandleRButtonUp", 22: "HandleRButtonHeld",
    23: "HandleRButtonUpAfterHeld", 24: "HandleWheelButtonDown",
    25: "HandleWheelButtonUp", 26: "HandleMouseMove",
    27: "HandleWheelMove", 28: "HandleKeyboardMsg",
    29: "HandleMouseLeave", 30: "OnDragDrop", 31: "GetDragDropCursor",
    32: "QueryDropOK", 33: "OnClickStick", 34: "GetClickStickCursor",
    35: "QueryClickStickDropOK", 36: "WndNotification",
    37: "OnWndNotification", 38: "Activate", 39: "Deactivate",
    40: "OnShow", 41: "OnMove", 42: "OnResize",
    43: "OnBeginMoveOrResize", 44: "OnCompleteMoveOrResize",
    45: "OnMinimizeBox", 46: "OnMaximizeBox", 47: "OnTileBox",
    48: "OnTile", 49: "OnSetFocus", 50: "OnKillFocus",
    51: "OnProcessFrame", 52: "OnVScroll", 53: "OnHScroll",
    54: "OnBroughtToTop", 55: "OnActivate", 56: "Show",
    57: "AboutToShow", 58: "AboutToHide", 59: "RequestDockInfo",
    60: "GetTooltip", 61: "ClickThroughMenuItemTriggered",
    62: "SetLocked", 63: "HitTest", 64: "GetHitTestRect",
    65: "GetInnerRect", 66: "GetClientRect", 67: "GetClientClipRect",
    68: "GetMinSize", 69: "GetMaxSize", 70: "GetUntileSize",
    71: "IsPointTransparent", 72: "ShouldProcessChildrenFrames",
    73: "ShouldProcessControllerFrame",
    74: "SetDrawTemplate", 75: "SetBGType", 76: "SetBGColor",
    77: "UpdateGeometry", 78: "Move", 79: "Minimize",
    80: "SetWindowText", 81: "SetTooltip",
    82: "Center", 83: "CenterVertically", 84: "CenterHorizontally",
    85: "Top", 86: "Bottom", 87: "Right", 88: "Left",
    89: "MoveToCursor", 90: "GetChildWndAt", 91: "GetSidlPiece",
    92: "GetWindowName", 93: "SetVScrollPos", 94: "SetHScrollPos",
    95: "AutoSetVScrollPos", 96: "AutoSetHScrollPos",
    97: "SetAttributesFromSidl", 98: "OnReloadSidl",
    99: "HasActivatedFirstTimeAlert", 100: "SetHasActivatedFirstTimeAlert",
    101: "GetMinClientSize", 102: "GetMaxClientSize",
    103: "GetActiveEditWnd", 104: "UpdateLayout",
}


def load_vtable_mapping(vtable_file):
    """Load vtable index -> function address mapping."""
    mapping = {}
    with open(vtable_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                idx = int(parts[0])
                addr = parts[1].strip().lower()
                mapping[addr] = idx
    return mapping


def load_decompilations(decompile_file):
    """Load batch decompilation output, split by function."""
    functions = {}
    current_addr = None
    current_code = []

    with open(decompile_file) as f:
        for line in f:
            if line.startswith("@@@ FUNC "):
                if current_addr and current_code:
                    functions[current_addr] = "\n".join(current_code)
                current_addr = line.split()[2].strip().lower()
                current_code = []
            else:
                current_code.append(line.rstrip())

    if current_addr and current_code:
        functions[current_addr] = "\n".join(current_code)

    return functions


def load_named_decompilations(decompile_file):
    """Load decompilations with function names (@@@ FUNC addr name @@@)."""
    functions = {}
    current_key = None
    current_code = []

    with open(decompile_file) as f:
        for line in f:
            if line.startswith("@@@ FUNC "):
                if current_key and current_code:
                    functions[current_key] = "\n".join(current_code)
                parts = line.split()
                addr = parts[2].strip().lower()
                name = parts[3] if len(parts) > 3 else "unknown"
                current_key = (addr, name.rstrip(" @"))
                current_code = []
            else:
                current_code.append(line.rstrip())

    if current_key and current_code:
        functions[current_key] = "\n".join(current_code)

    return functions


def main():
    vtable_file = "/tmp/cxwnd_vtable_addrs.txt"
    decompile_file = "/tmp/cxwnd_all_decompiled.txt"
    exports_file = "/tmp/cxwnd_exports_decompiled.txt"

    if not os.path.exists(decompile_file):
        print("Waiting for decompilation to complete...")
        return

    vtable_map = load_vtable_mapping(vtable_file)
    functions = load_decompilations(decompile_file)

    # Also load named export decompilations if available
    export_functions = {}
    if os.path.exists(exports_file):
        export_functions = load_named_decompilations(exports_file)
        print(f"Loaded {len(export_functions)} named export functions")

    print(f"Loaded {len(functions)} vtable functions")
    print(f"Vtable mapping: {len(vtable_map)} entries")

    # Process each function
    all_findings = []
    for addr, code in functions.items():
        vtable_idx = vtable_map.get(addr)
        func_name = VTABLE_NAMES.get(vtable_idx, f"vfunc_{vtable_idx}") if vtable_idx is not None else "unknown"

        findings = parse_decompilation(code, func_name)

        # For setter/getter naming: only name the field that's directly written/read
        # A setter that writes param2 to ONE offset is reliable even if the function
        # reads other offsets as side effects (e.g. SetZLayer writes 0x244 then calls manager)
        setters = [f for f in findings if f["type"] == "setter" and 0x030 <= f["offset"] < 0x268]
        getters = [f for f in findings if f["type"] == "getter" and 0x030 <= f["offset"] < 0x268]

        for f in findings:
            f["func_addr"] = addr
            f["func_name"] = func_name
            f["vtable_idx"] = vtable_idx

            # Name from Set functions: only the setter target (param2 write)
            if func_name.startswith("Set") and f["type"] == "setter" and len(setters) == 1:
                f["probable_field"] = func_name[3:]
                f["confidence"] = "HIGH"
            # Name from Get functions: only the getter return value
            elif func_name.startswith("Get") and f["type"] == "getter" and len(getters) == 1:
                f["probable_field"] = func_name[3:]
                f["confidence"] = "HIGH"

        all_findings.extend(findings)

    # Process named export functions
    for (addr, name), code in export_functions.items():
        findings = parse_decompilation(code, name)

        setters_e = [f for f in findings if f["type"] == "setter" and 0x030 <= f["offset"] < 0x268]
        getters_e = [f for f in findings if f["type"] == "getter" and 0x030 <= f["offset"] < 0x268]

        for f in findings:
            f["func_addr"] = addr
            f["func_name"] = name
            f["vtable_idx"] = None

            if name.startswith("Set") and f["type"] == "setter" and len(setters_e) == 1:
                f["probable_field"] = name[3:]
                f["confidence"] = "HIGH"
            elif name.startswith("Get") and f["type"] == "getter" and len(getters_e) == 1:
                f["probable_field"] = name[3:]
                f["confidence"] = "HIGH"

        all_findings.extend(findings)

    # Merge by offset
    by_offset = {}
    for f in all_findings:
        off = f["offset"]
        if off < 0x030 or off >= 0x300:  # filter to CXWnd member range
            continue
        if off not in by_offset:
            by_offset[off] = []
        by_offset[off].append(f)

    # Print results
    print(f"\n{'='*80}")
    print(f"FIELD ACCESS MAP (from vtable function analysis)")
    print(f"{'='*80}")

    for off in sorted(by_offset.keys()):
        findings = by_offset[off]
        # Pick best finding
        best = max(findings, key=lambda f: (
            {"HIGH": 3, "MED": 2, "LOW": 1}.get(f["confidence"], 0),
            1 if f.get("probable_field") else 0
        ))

        name = best.get("probable_field", "?")
        conf = best["confidence"]
        access = best["type"]
        size = best["size"]
        func = best["func_name"]

        marker = "*" if conf == "HIGH" else " "
        print(f"{marker} 0x{off:03X} ({size}B) = {name:30s} [{conf:4s}] via {func} ({access})")

    # Summary
    high = sum(1 for findings in by_offset.values()
               if any(f["confidence"] == "HIGH" for f in findings))
    med = sum(1 for findings in by_offset.values()
              if all(f["confidence"] != "HIGH" for f in findings)
              and any(f["confidence"] == "MED" for f in findings))
    print(f"\nTotal offsets found: {len(by_offset)}")
    print(f"  HIGH confidence: {high}")
    print(f"  MED confidence: {med}")
    print(f"  Other: {len(by_offset) - high - med}")


if __name__ == "__main__":
    main()
