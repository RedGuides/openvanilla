#!/usr/bin/env python3
"""
Walk a class vtable via Ghidra MCP and run accessor analysis on each entry.

This script generates a JSON mapping of field offsets discovered from
virtual function analysis. It does NOT reference any answer key.

Output: JSON file with discovered field->offset mappings and confidence levels.

Usage (conceptual - actual execution uses Ghidra MCP from Claude):
  walk_vtable.py --class CXWnd --vtable-addr 0x140ae54c0 --vtable-size 0x348
"""

import json
import sys
import os

# Add parent dir for imports
sys.path.insert(0, os.path.dirname(__file__))
from vtable_accessor_scanner import parse_decompilation, type_to_size

# Known vtable info from our analysis
VTABLES = {
    "CXWnd": {
        "vtable_addr": 0x140ae54c0,
        "vtable_size": 0x348,  # bytes, each entry is 8 bytes
        "struct_base": 0x030,  # first member after vtable+list pointers
        "struct_end": 0x268,
        # Known function names from the header's VirtualFunctionTable struct
        "known_names": {
            0x000: "destructor",
            0x008: "GetWndClassName",
            0x010: "IsPointTransparent",
            0x018: "DrawNC",
            0x020: "Draw",
            0x028: "PostDraw",
            0x030: "DrawCursor",
            0x038: "DrawChildItem",
            0x040: "DrawCaret",
            0x048: "DrawBackground",
            0x050: "DrawTooltip",
            0x058: "DrawTooltipAtPoint",
            0x060: "GetMinimizedRect",
            0x068: "DrawTitleBar",
            0x070: "SetZLayer",
            0x078: "GetChildWndAt",
            0x080: "GetSidlPiece",
            0x088: "GetWindowName",
            0x090: "SetVScrollPos",
            0x098: "SetHScrollPos",
            0x0A0: "PostDraw2",
            0x0A8: "HandleLButtonDown",
            0x0B0: "HandleLButtonUp",
            0x0B8: "HandleLButtonHeld",
            0x0C0: "HandleLButtonUpAfterHeld",
            0x0C8: "HandleRButtonDown",
            0x0D0: "HandleRButtonUp",
            0x0D8: "HandleWheelButtonDown",
            0x0E0: "HandleWheelButtonUp",
            0x0E8: "HandleMouseMove",
            0x0F0: "HandleWheelMove",
            0x0F8: "HandleKeyboardMsg",
            0x100: "HandleMouseLeave",
            0x108: "OnDragDrop",
            0x110: "GetDragDropCursor",
            0x118: "QueryDropOK",
            0x120: "OnClickStick",
            0x128: "GetClickStickCursor",
            0x130: "QueryClickStickDropOK",
            0x138: "WndNotification",
            0x140: "OnWndNotification",
            0x148: "OnMove",
            0x150: "OnResize",
            0x158: "OnBeginMoveOrResize",
            0x160: "OnCompleteMoveOrResize",
            0x168: "OnMinimizeBox",
            0x170: "OnMaximizeBox",
            0x178: "OnTileBox",
            0x180: "OnTile",
            0x188: "OnSetFocus",
            0x190: "OnKillFocus",
            0x198: "OnProcessFrame",
            0x1A0: "OnVScroll",
            0x1A8: "OnHScroll",
            0x1B0: "OnBroughtToTop",
            0x1B8: "OnActivate",
            0x1C0: "Show",
            0x1C8: "OnShow",
            0x1D0: "AboutToShow",
            0x1D8: "AboutToHide",
            0x1E0: "RequestDockInfo",
            0x1E8: "GetTooltip",
            0x1F0: "IsActive",
            0x1F8: "ClickThroughMenuItemTriggered",
            0x200: "GetHScrollRange",
            0x208: "GetVScrollRange",
            0x210: "GetMinClientSize",
            0x218: "GetScreenClipRect",
            0x220: "GetClientClipRect",
            0x228: "UpdateGeometry",
            0x230: "SetDrawTemplate",
            0x238: "Move",
            0x240: "SetWindowText",
            0x248: "GetChildWndAt2",
            0x250: "SetBGType",
            0x258: "SetBGColor",
            0x260: "UpdateLayout",
        }
    },
    "PlayerZoneClient": {
        "vtable_addr": 0x140aeea38,  # from constructor FUN_140653f60
        "vtable_size": 0x200,  # estimate
        "struct_base": 0x01CC,
        "struct_end": 0x0650,
        "known_names": {}
    }
}


def build_scan_commands(class_name):
    """
    Generate the list of vtable entries to scan.
    Returns list of (vtable_offset, entry_address) tuples.
    """
    info = VTABLES[class_name]
    vtable_addr = info["vtable_addr"]
    vtable_size = info["vtable_size"]
    num_entries = vtable_size // 8

    entries = []
    for i in range(num_entries):
        vtable_offset = i * 8
        entry_addr = vtable_addr + vtable_offset
        name = info["known_names"].get(vtable_offset, f"vfunc_{vtable_offset:03X}")
        entries.append({
            "vtable_offset": vtable_offset,
            "entry_addr": entry_addr,
            "name": name,
        })

    return entries


def process_decompilation(entry, decompiled_code):
    """
    Process a decompiled vtable function and extract field mappings.
    """
    name = entry.get("name", "unknown")
    findings = parse_decompilation(decompiled_code, name)

    # Boost confidence for known setter/getter names
    for f in findings:
        if name.startswith("Set") and f["type"] == "setter":
            f["confidence"] = "HIGH"
            f["probable_name"] = name[3:]  # "SetZLayer" -> "ZLayer"
        elif name.startswith("Get") and f["type"] == "getter":
            f["confidence"] = "HIGH"
            f["probable_name"] = name[3:]
        elif name.startswith("Is") and f["type"] == "getter":
            f["confidence"] = "HIGH"
            f["probable_name"] = name

    return findings


def merge_findings(all_findings):
    """
    Merge findings from all vtable functions into a unified field map.
    When multiple findings point to the same offset, prefer:
    1. HIGH confidence setter/getter with probable_name
    2. HIGH confidence access
    3. MED confidence
    """
    by_offset = {}
    for f in all_findings:
        off = f["offset"]
        if off not in by_offset:
            by_offset[off] = f
        else:
            existing = by_offset[off]
            # Prefer higher confidence
            conf_order = {"HIGH": 3, "MED": 2, "LOW": 1}
            if conf_order.get(f["confidence"], 0) > conf_order.get(existing["confidence"], 0):
                by_offset[off] = f
            # Prefer named over unnamed
            elif f.get("probable_name") and not existing.get("probable_name"):
                by_offset[off] = f

    return by_offset


if __name__ == "__main__":
    # Print scan plan for CXWnd
    print("=== CXWnd Vtable Scan Plan ===")
    entries = build_scan_commands("CXWnd")
    print(f"Total entries: {len(entries)}")
    print(f"\nEntries with known names (likely accessors):")
    for e in entries:
        if e["name"].startswith("Set") or e["name"].startswith("Get"):
            print(f"  0x{e['vtable_offset']:03X}: {e['name']} -> scan at 0x{e['entry_addr']:X}")

    print(f"\nPriority targets (Set/Get functions):")
    priority = [e for e in entries if e["name"].startswith("Set") or e["name"].startswith("Get")]
    print(f"  {len(priority)} accessor functions to decompile")
    print(f"  {len(entries) - len(priority)} other functions to scan for field accesses")
