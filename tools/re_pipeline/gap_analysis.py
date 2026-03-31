#!/usr/bin/env python3
"""
gap_analysis.py - Place CXWnd fields using size/alignment constraints.

For each build with ground truth:
1. Identify fields that have HIGH accessor evidence
2. Place those at their known offsets
3. For remaining fields, check if size/alignment forces unique placement
4. Add gap_analysis evidence records for forced placements

Then cascade: if a field is resolved in build A and we have a BinDiff link
to build B, translate the identifying function address.
"""

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

# Type → (size, alignment) mapping for MSVC x64
TYPE_SIZES = {
    'bool': (1, 1),
    'uint8_t': (1, 1),
    'int': (4, 4),
    'uint32_t': (4, 4),
    'COLORREF': (4, 4),
    'float': (4, 4),
    'CXRect': (16, 4),
    'CXSize': (8, 4),
    'CXStr': (8, 8),
    'int64_t': (8, 8),
    'CXWnd*': (8, 8),
    'CXWndDrawTemplate*': (8, 8),
    'CLayoutStrategy*': (8, 8),
    'CStaticTintedBlendAnimationTemplate*': (8, 8),
    'CTextObjectInterface*': (8, 8),
    'CTextureFont*': (8, 8),
    'ControllerBase*': (8, 8),
    'CTextureAnimation*': (8, 8),
    'void*': (8, 8),
    'ArrayClass2<uint32_t>': (32, 8),
}

# Fallback: any pointer type
def get_type_size(field_type):
    if field_type in TYPE_SIZES:
        return TYPE_SIZES[field_type]
    if field_type and '*' in field_type:
        return (8, 8)
    return None


def run_gap_analysis(db, binary_id, build_date, class_name='CXWnd',
                     struct_lo=0x030, struct_hi=0x268, dry_run=False):
    """Run gap analysis for one build. Returns count of fields placed."""

    # Get all member offsets for this build (ground truth)
    all_members = db.get_all_members(class_name, binary_id)
    if not all_members:
        return 0

    # Filter to instance members in struct range
    members = [m for m in all_members if struct_lo <= m['offset_val'] < struct_hi]

    # Get fields that already have HIGH evidence for this build
    high_fields = set()
    rows = db.conn.execute("""
        SELECT DISTINCT sm.field_name
        FROM evidence_records er
        JOIN struct_members sm ON er.member_id = sm.id
        WHERE er.binary_id = ? AND sm.class_name = ? AND er.confidence = 'HIGH'
    """, (binary_id, class_name)).fetchall()
    for r in rows:
        high_fields.add(r['field_name'])

    # Build offset map: offset → (field_name, field_type, size, align)
    placed = {}  # offset → field_name (HIGH evidence fields)
    unplaced = {}  # offset → (field_name, field_type, size, align)

    for m in members:
        ft = m['field_type']
        ts = get_type_size(ft) if ft else None
        if ts is None:
            continue  # Skip fields with unknown type sizes

        size, align = ts
        off = m['offset_val']

        if m['field_name'] in high_fields:
            placed[off] = m['field_name']
        else:
            unplaced[off] = (m['field_name'], ft, size, align)

    if not unplaced:
        return 0

    # Sort placed offsets to find gaps
    placed_list = sorted(placed.items())  # [(offset, field_name), ...]

    # For gap analysis: identify stretches where unplaced fields sit between placed fields
    # A field is "forced" if it's the only unplaced field that fits in a gap
    forced = []

    # Build sorted list of ALL member offsets and their sizes
    all_sorted = []
    for m in members:
        ft = m['field_type']
        ts = get_type_size(ft) if ft else None
        if ts:
            all_sorted.append((m['offset_val'], m['field_name'], ts[0], ts[1],
                              m['field_name'] in high_fields))
    all_sorted.sort()

    # Walk through consecutive unplaced fields between placed anchors
    # Group unplaced fields that are between the same pair of placed fields
    groups = []
    current_group = []
    last_placed = None

    for off, fname, size, align, is_placed in all_sorted:
        if is_placed:
            if current_group:
                groups.append((last_placed, current_group, off))
                current_group = []
            last_placed = off
        else:
            current_group.append((off, fname, size, align))

    # Handle trailing unplaced after last placed
    if current_group:
        groups.append((last_placed, current_group, struct_hi))

    # For each group: if only one field, it's forced by position
    for before_off, group_fields, after_off in groups:
        if len(group_fields) == 1:
            off, fname, size, align = group_fields[0]
            forced.append((off, fname, 'single field in gap'))
            continue

        # Multiple unplaced fields in this gap
        # Check if each field's size+alignment makes it the only valid placement
        # at its known offset (i.e., no other unplaced field could fit there)
        for off, fname, size, align in group_fields:
            # How many other unplaced fields in this group could fit at this offset?
            candidates = []
            for off2, fname2, size2, align2 in group_fields:
                # Could fname2 sit at offset `off`?
                # Check alignment: off must be aligned to align2
                if align2 > 1 and off % align2 != 0:
                    continue
                # Check that it doesn't overlap next field
                candidates.append(fname2)

            if len(candidates) == 1 and candidates[0] == fname:
                forced.append((off, fname, f'only field with align={align} size={size} fits at 0x{off:03x}'))

    # Add evidence records for forced placements
    added = 0
    for off, fname, reason in forced:
        if dry_run:
            print(f"  FORCED: {fname} at 0x{off:03x} ({reason})")
            continue

        # Check if gap_analysis evidence already exists
        existing = db.conn.execute("""
            SELECT er.id FROM evidence_records er
            JOIN struct_members sm ON er.member_id = sm.id
            JOIN function_identities fi ON er.func_id = fi.id
            WHERE er.binary_id = ? AND sm.class_name = ? AND sm.field_name = ?
              AND fi.func_name = 'gap_analysis'
        """, (binary_id, class_name, fname)).fetchone()

        if not existing:
            db.add_evidence(
                binary_id=binary_id,
                class_name=class_name,
                field_name=fname,
                func_name='gap_analysis',
                func_addr=off,  # Use offset as pseudo-address
                evidence_type='access',
                decompile_line=f'gap_analysis: {reason}',
                confidence='HIGH'
            )
            added += 1

    return added


def run_cascade(db, class_name='CXWnd', struct_lo=0x030, struct_hi=0x268):
    """Cascade resolution: propagate identifications across builds via BinDiff.

    If field F is identified in build A (HIGH evidence), and build A→B has
    a BinDiff pair, check if the identifying function exists in B.
    If so, add cascade evidence for F in B.
    """
    # Get all BinDiff pairs
    pairs = db.conn.execute("""
        SELECT DISTINCT old_binary, new_binary FROM bindiff_matches
    """).fetchall()

    added = 0
    for pair in pairs:
        old_bid, new_bid = pair['old_binary'], pair['new_binary']

        # Get fields with HIGH evidence in old but not new
        old_high = set(r['field_name'] for r in db.conn.execute("""
            SELECT DISTINCT sm.field_name FROM evidence_records er
            JOIN struct_members sm ON er.member_id = sm.id
            WHERE er.binary_id = ? AND sm.class_name = ? AND er.confidence = 'HIGH'
        """, (old_bid, class_name)).fetchall())

        new_high = set(r['field_name'] for r in db.conn.execute("""
            SELECT DISTINCT sm.field_name FROM evidence_records er
            JOIN struct_members sm ON er.member_id = sm.id
            WHERE er.binary_id = ? AND sm.class_name = ? AND er.confidence = 'HIGH'
        """, (new_bid, class_name)).fetchall())

        missing_in_new = old_high - new_high

        if not missing_in_new:
            continue

        # For each missing field, find the identifying function in old
        for fname in missing_in_new:
            # Get the function that identifies this field in old build
            func_rows = db.conn.execute("""
                SELECT fi.func_name, fi.func_addr FROM evidence_records er
                JOIN struct_members sm ON er.member_id = sm.id
                JOIN function_identities fi ON er.func_id = fi.id
                WHERE er.binary_id = ? AND sm.class_name = ? AND sm.field_name = ?
                  AND er.confidence = 'HIGH'
                LIMIT 1
            """, (old_bid, class_name, fname)).fetchone()

            if not func_rows:
                continue

            old_addr = func_rows['func_addr']
            func_name = func_rows['func_name']

            # Translate via BinDiff
            new_addr = db.translate_address(old_bid, new_bid, old_addr)
            if new_addr is None:
                # Try reverse direction
                new_addr = db.translate_address(new_bid, old_bid, old_addr)
                if new_addr is not None:
                    # This means old_addr exists in new→old direction, wrong way
                    new_addr = None

            if new_addr is None:
                continue

            # Check if cascade evidence already exists
            existing = db.conn.execute("""
                SELECT er.id FROM evidence_records er
                JOIN struct_members sm ON er.member_id = sm.id
                JOIN function_identities fi ON er.func_id = fi.id
                WHERE er.binary_id = ? AND sm.class_name = ? AND sm.field_name = ?
                  AND fi.func_name LIKE 'cascade_%'
            """, (new_bid, class_name, fname)).fetchone()

            if not existing:
                db.add_evidence(
                    binary_id=new_bid,
                    class_name=class_name,
                    field_name=fname,
                    func_name=f'cascade_{func_name}',
                    func_addr=new_addr,
                    evidence_type='access',
                    decompile_line=f'cascade from {func_name} via BinDiff',
                    confidence='HIGH'
                )
                added += 1

    return added


def main():
    db = EQXrefDB()

    # Get all builds with ground truth
    builds = db.conn.execute("""
        SELECT id, build_date FROM binaries
        WHERE server = 'live' AND eqgame_h IS NOT NULL
        ORDER BY build_date
    """).fetchall()

    print(f"Running gap analysis on {len(builds)} builds...")

    total_gap = 0
    for b in builds:
        bid, bdate = b['id'], b['build_date']
        count = run_gap_analysis(db, bid, bdate)
        if count > 0:
            print(f"  {bdate}: {count} gap-forced fields added")
            total_gap += count

    print(f"\nGap analysis total: {total_gap} evidence records added")

    # Run cascade resolution iteratively until no more progress
    print(f"\nRunning cascade resolution...")
    iteration = 0
    while True:
        iteration += 1
        count = run_cascade(db)
        if count == 0:
            break
        print(f"  Iteration {iteration}: {count} cascade records added")

    # Final stats
    print(f"\n{'='*60}")
    print("Final coverage:")
    rows = db.conn.execute("""
        SELECT sm.field_name, COUNT(DISTINCT er.binary_id) as bc
        FROM evidence_records er
        JOIN struct_members sm ON er.member_id = sm.id
        WHERE sm.class_name = 'CXWnd' AND er.confidence = 'HIGH'
          AND EXISTS (
            SELECT 1 FROM member_offsets mo
            WHERE mo.member_id = sm.id AND mo.offset_val >= 0x030 AND mo.offset_val < 0x268
          )
        GROUP BY sm.field_name
        ORDER BY bc DESC
    """).fetchall()

    by_count = defaultdict(list)
    for r in rows:
        by_count[r['bc']].append(r['field_name'])

    total_fields = db.conn.execute("""
        SELECT COUNT(DISTINCT sm.field_name) FROM member_offsets mo
        JOIN struct_members sm ON mo.member_id = sm.id
        WHERE sm.class_name = 'CXWnd' AND mo.offset_val >= 0x030 AND mo.offset_val < 0x268
    """).fetchone()[0]

    covered = len(rows)
    at_5plus = sum(1 for r in rows if r['bc'] >= 5)

    print(f"Total instance fields: {total_fields}")
    print(f"Fields with any HIGH evidence: {covered}")
    print(f"Fields with HIGH in 5+ builds: {at_5plus}")

    # Show fields with < 5 builds
    sparse = [(r['field_name'], r['bc']) for r in rows if r['bc'] < 5]
    if sparse:
        print(f"\nFields with < 5 builds HIGH evidence ({len(sparse)}):")
        for fname, bc in sorted(sparse, key=lambda x: x[1]):
            print(f"  {fname}: {bc}")

    # Show fields with NO evidence
    all_instance = set(r[0] for r in db.conn.execute("""
        SELECT DISTINCT sm.field_name FROM member_offsets mo
        JOIN struct_members sm ON mo.member_id = sm.id
        WHERE sm.class_name = 'CXWnd' AND mo.offset_val >= 0x030 AND mo.offset_val < 0x268
    """).fetchall())
    no_evidence = all_instance - set(r['field_name'] for r in rows)
    if no_evidence:
        print(f"\nFields with NO HIGH evidence ({len(no_evidence)}):")
        for fname in sorted(no_evidence):
            print(f"  {fname}")

    db.close()


if __name__ == '__main__':
    main()
