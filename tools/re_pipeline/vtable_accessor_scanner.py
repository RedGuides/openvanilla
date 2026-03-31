#!/usr/bin/env python3
"""
Vtable Accessor Scanner

Walks a class vtable, decompiles each function via Ghidra MCP,
and identifies simple getter/setter patterns to map field names
to binary offsets.

Patterns detected:
- Setter: *(type*)(param1 + OFFSET) = param2  ->  field at OFFSET, size = sizeof(type)
- Getter: return *(type*)(param1 + OFFSET)     ->  field at OFFSET, size = sizeof(type)
- Simple forwarder: calls another function with param1 + OFFSET

Usage:
  This script outputs field mappings. It does NOT look at any answer key.
  Validation against brainiac's layouts is done separately.
"""

import re
import json
import sys
import subprocess

def ghidra_get_xrefs_from(address):
    """Get xrefs from an address via Ghidra MCP (called externally)."""
    # This will be called via the MCP tool in the parent context
    pass

def parse_decompilation(code, func_name="unknown"):
    """
    Parse a Ghidra decompilation to find field access patterns.

    Returns list of:
      {"type": "setter"|"getter"|"read"|"write",
       "offset": int,
       "size": int,
       "field_type": str,
       "confidence": "HIGH"|"MED"|"LOW",
       "evidence": str}
    """
    findings = []

    # Normalize the code
    lines = code.strip().split('\n')

    # All param/arg variants
    P1 = r'(?:param_1|param1|arg1)'
    P2 = r'(?:param_2|param2|arg2|in_DL|\(int32_t\)\s*arg2)'

    # Pattern 1: Simple setter - *(type*)(param + 0xOFFSET) = param2
    setter_pat = re.compile(
        rf'\*\((\w+)\s*\*\)\s*\(\s*{P1}\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*\)\s*=\s*{P2}',
        re.IGNORECASE
    )

    # Pattern 1b: Setter via longlong cast
    setter_cast_pat = re.compile(
        rf'\*\((\w+)\s*\*\)\s*\(\s*\((?:longlong|int64_t)\)\s*{P1}\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*\)\s*=\s*{P2}',
        re.IGNORECASE
    )

    # Pattern 2: Simple getter - return *(type*)(param + 0xOFFSET)
    getter_pat = re.compile(
        rf'return\s+\*\((\w+)\s*\*\)\s*\(\s*(?:\((?:longlong|int64_t)\)\s*)?{P1}\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*\)',
        re.IGNORECASE
    )

    # Pattern 2b: Return address getter - return param + 0xOFFSET (returns pointer to field)
    addr_getter_pat = re.compile(
        rf'return\s+{P1}\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*;',
        re.IGNORECASE
    )

    # Pattern 3: Pointer arithmetic - param_1[N] where param is ptr type
    # param_1[0x25] with undefined8* means offset 0x25 * 8 = 0x128
    array_write_pat = re.compile(
        r'(?:param_1|param1)\[(?:0x)?([0-9a-fA-F]+)\]\s*=\s*(?:param_2|param2|arg2)',
        re.IGNORECASE
    )

    # Pattern 4: Direct member write with byte offset
    direct_write_pat = re.compile(
        r'\*\((\w+)\s*\*\)\s*\(\s*(?:\(longlong\)\s*)?(?:param_1|param1)\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*\)\s*=\s*(.+?);',
        re.IGNORECASE
    )

    # Pattern 5: Read for comparison or return
    direct_read_pat = re.compile(
        rf'\*\((\w+)\s*\*?\s*\*\)\s*\(\s*(?:\((?:longlong|int64_t)\)\s*)?{P1}\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*\)',
        re.IGNORECASE
    )

    for line in lines:
        line = line.strip()

        # Check setter patterns
        for pat in [setter_pat, setter_cast_pat]:
            m = pat.search(line)
            if m:
                field_type = m.group(1)
                offset = int(m.group(2), 16)
                size = type_to_size(field_type)
                findings.append({
                    "type": "setter",
                    "offset": offset,
                    "size": size,
                    "field_type": field_type,
                    "confidence": "HIGH",
                    "evidence": f"setter in {func_name}: {line.strip()}"
                })

        # Check address getter (return arg1 + offset)
        m = addr_getter_pat.search(line)
        if m:
            offset = int(m.group(1), 16)
            findings.append({
                "type": "getter",
                "offset": offset,
                "size": 0,  # unknown, returns pointer to field
                "field_type": "address",
                "confidence": "HIGH",
                "evidence": f"addr getter in {func_name}: {line.strip()}"
            })

        # Check getter patterns
        m = getter_pat.search(line)
        if m:
            field_type = m.group(1)
            offset = int(m.group(2), 16)
            size = type_to_size(field_type)
            findings.append({
                "type": "getter",
                "offset": offset,
                "size": size,
                "field_type": field_type,
                "confidence": "HIGH",
                "evidence": f"getter in {func_name}: {line.strip()}"
            })

    # Count total field accesses (reads + writes) for ALL functions
    all_accesses = []
    for line in lines:
        for m in direct_read_pat.finditer(line):
            field_type = m.group(1)
            offset = int(m.group(2), 16)
            if 0x030 <= offset < 0x1000:  # reasonable CXWnd/PZC member range
                all_accesses.append({
                    "offset": offset,
                    "size": type_to_size(field_type),
                    "field_type": field_type,
                    "line": line.strip()
                })

    # For short functions (< 10 lines), all accesses are MED confidence
    code_lines = [l for l in lines if l.strip() and not l.strip().startswith('//') and not l.strip().startswith('{') and not l.strip().startswith('}')]
    if len(code_lines) <= 8:
        for a in all_accesses:
            already_found = any(f["offset"] == a["offset"] for f in findings)
            if not already_found:
                findings.append({
                    "type": "access",
                    "offset": a["offset"],
                    "size": a["size"],
                    "field_type": a["field_type"],
                    "confidence": "MED",
                    "evidence": f"simple function {func_name} accesses 0x{a['offset']:X}: {a['line']}"
                })
    else:
        # For complex functions, report all accesses as LOW confidence
        # IMPORTANT: do NOT assign probable_field names from complex functions.
        # A function like GetScreenClipRect touches 10+ fields -- we can't tell
        # which offset corresponds to which field name from the function name alone.
        for a in all_accesses:
            already_found = any(f["offset"] == a["offset"] for f in findings)
            if not already_found:
                findings.append({
                    "type": "access",
                    "offset": a["offset"],
                    "size": a["size"],
                    "field_type": a["field_type"],
                    "confidence": "LOW",
                    "evidence": f"complex function {func_name} accesses 0x{a['offset']:X}: {a['line']}",
                    # No probable_field -- complex functions don't reliably name fields
                })

    return findings


def type_to_size(ghidra_type):
    """Convert Ghidra type name to byte size."""
    t = ghidra_type.lower().replace('*', '').strip()
    sizes = {
        'undefined1': 1, 'undefined2': 2, 'undefined4': 4, 'undefined8': 8,
        'byte': 1, 'char': 1, 'bool': 1, 'uint8_t': 1,
        'short': 2, 'ushort': 2, 'uint16_t': 2, 'int16_t': 2, 'word': 2,
        'int': 4, 'uint': 4, 'uint32_t': 4, 'int32_t': 4, 'dword': 4,
        'float': 4, 'colorref': 4,
        'longlong': 8, 'ulonglong': 8, 'int64_t': 8, 'uint64_t': 8,
        'qword': 8, 'double': 8,
        'undefined': 1,
    }
    return sizes.get(t, 8 if 'ptr' in ghidra_type.lower() or '*' in ghidra_type else 4)


def extract_func_name_hint(decompiled_code):
    """Try to extract a meaningful function name from the decompilation."""
    # Look for the function signature line
    m = re.search(r'(?:void|int|bool|float|undefined\d?)\s+(\w+)\s*\(', decompiled_code)
    if m:
        return m.group(1)
    return "unknown"


# Vtable entry format for output
class VtableEntry:
    def __init__(self, vtable_offset, func_addr, func_name=None):
        self.vtable_offset = vtable_offset
        self.func_addr = func_addr
        self.func_name = func_name
        self.decompilation = None
        self.findings = []

    def to_dict(self):
        return {
            "vtable_offset": f"0x{self.vtable_offset:03X}",
            "func_addr": f"0x{self.func_addr:X}",
            "func_name": self.func_name,
            "findings": self.findings
        }


if __name__ == "__main__":
    # Test the parser with a known decompilation
    test_code = """
void FUN_1405c7f20(longlong *param_1,undefined4 param_2)
{
  *(undefined4 *)((longlong)param_1 + 0x244) = param_2;
  FUN_1405e7fd0(*(longlong *)PTR_DAT_140d646c8,param_1,'\\0');
  return;
}
"""
    findings = parse_decompilation(test_code, "SetZLayer")
    print("Test parse (SetZLayer):")
    for f in findings:
        print(f"  {f['type']}: offset=0x{f['offset']:03X}, size={f['size']}B, conf={f['confidence']}")
        print(f"    {f['evidence']}")

    # Test with a getter
    test_getter = """
float FUN_1402664b0(longlong param_1)
{
    return *(float *)(param_1 + 0x398);
}
"""
    findings = parse_decompilation(test_getter, "GetViewHeight")
    print("\nTest parse (GetViewHeight):")
    for f in findings:
        print(f"  {f['type']}: offset=0x{f['offset']:03X}, size={f['size']}B, conf={f['confidence']}")
        print(f"    {f['evidence']}")

    # Test with AddTransitionWindow pattern
    test_complex = """
undefined8 FUN_1405e7c80(longlong param_1,longlong param_2)
{
  if (*(char *)(param_2 + 0x198) != '\\0') {
    return 0xffffffff;
  }
  *(undefined1 *)(param_2 + 0x198) = 1;
  if (*(int *)(param_2 + 0x244) < *(int *)(*(longlong *)(*(longlong *)(param_1 + 0x40) + lVar5 * 8) + 0x244))
    goto somewhere;
  return 0;
}
"""
    findings = parse_decompilation(test_complex, "AddTransitionWindow")
    print("\nTest parse (AddTransitionWindow):")
    for f in findings:
        print(f"  {f['type']}: offset=0x{f['offset']:03X}, size={f['size']}B, conf={f['confidence']}")
        print(f"    {f['evidence']}")
