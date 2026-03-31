#!/usr/bin/env python3
"""
eq_xref_db.py - Persistent cross-reference database for EQ struct member tracking.

Tracks where each struct member lives in each binary version and which
functions access it. Accumulates knowledge across patches so each
successive patch day gets easier.

All other scripts should import from here -- don't call sqlite3.connect directly.
"""

import sqlite3
import re
import os
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'eq_xref.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS binaries (
    id           INTEGER PRIMARY KEY,
    build_date   TEXT    UNIQUE NOT NULL,
    server       TEXT    NOT NULL DEFAULT 'live',
    binary_path  TEXT    NOT NULL,
    eqgame_h     TEXT,
    client_date  INTEGER,
    image_base   INTEGER DEFAULT 0x140000000,
    added_at     TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS struct_members (
    id           INTEGER PRIMARY KEY,
    class_name   TEXT    NOT NULL,
    field_name   TEXT    NOT NULL,
    field_type   TEXT,
    field_size   INTEGER,
    notes        TEXT,
    UNIQUE(class_name, field_name)
);

CREATE TABLE IF NOT EXISTS member_offsets (
    id           INTEGER PRIMARY KEY,
    binary_id    INTEGER NOT NULL REFERENCES binaries(id),
    member_id    INTEGER NOT NULL REFERENCES struct_members(id),
    offset_val   INTEGER NOT NULL,
    confidence   TEXT    NOT NULL
                 CHECK(confidence IN ('GROUND_TRUTH','HIGH','MED','LOW')),
    source       TEXT,
    UNIQUE(binary_id, member_id)
);

CREATE TABLE IF NOT EXISTS function_identities (
    id           INTEGER PRIMARY KEY,
    binary_id    INTEGER NOT NULL REFERENCES binaries(id),
    func_name    TEXT    NOT NULL,
    func_addr    INTEGER NOT NULL,
    UNIQUE(binary_id, func_name)
);

CREATE TABLE IF NOT EXISTS evidence_records (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER NOT NULL REFERENCES binaries(id),
    member_id       INTEGER NOT NULL REFERENCES struct_members(id),
    func_id         INTEGER NOT NULL REFERENCES function_identities(id),
    evidence_type   TEXT    NOT NULL
                    CHECK(evidence_type IN ('setter','getter','ini_key','destructor','xref','access')),
    decompile_line  TEXT,
    confidence      TEXT    NOT NULL
                    CHECK(confidence IN ('HIGH','MED','LOW'))
);

CREATE TABLE IF NOT EXISTS bindiff_matches (
    id           INTEGER PRIMARY KEY,
    old_binary   INTEGER NOT NULL REFERENCES binaries(id),
    new_binary   INTEGER NOT NULL REFERENCES binaries(id),
    old_addr     INTEGER NOT NULL,
    new_addr     INTEGER NOT NULL,
    similarity   REAL,
    UNIQUE(old_binary, new_binary, old_addr)
);

CREATE INDEX IF NOT EXISTS idx_offsets_binary_offset ON member_offsets(binary_id, offset_val);
CREATE INDEX IF NOT EXISTS idx_offsets_member ON member_offsets(member_id);
CREATE INDEX IF NOT EXISTS idx_evidence_member ON evidence_records(member_id);
CREATE INDEX IF NOT EXISTS idx_bindiff_lookup ON bindiff_matches(old_binary, old_addr);
CREATE INDEX IF NOT EXISTS idx_func_binary ON function_identities(binary_id, func_name);
"""


class EQXrefDB:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = os.path.abspath(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    # -- Build registration --

    def add_binary(self, build_date: str, binary_path: str,
                   eqgame_h_path: str = None, server: str = 'live',
                   client_date: int = None) -> int:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO binaries (build_date, server, binary_path, eqgame_h, client_date)
               VALUES (?, ?, ?, ?, ?)""",
            (build_date, server, binary_path, eqgame_h_path, client_date))
        self.conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        return self.get_binary_id(build_date)

    def get_binary_id(self, build_date: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT id FROM binaries WHERE build_date = ?", (build_date,)).fetchone()
        return row['id'] if row else None

    def list_binaries(self) -> list:
        rows = self.conn.execute(
            "SELECT * FROM binaries ORDER BY build_date").fetchall()
        return [dict(r) for r in rows]

    # -- Member catalog --

    def ensure_member(self, class_name: str, field_name: str,
                      field_type: str = None, field_size: int = None) -> int:
        self.conn.execute(
            """INSERT OR IGNORE INTO struct_members (class_name, field_name, field_type, field_size)
               VALUES (?, ?, ?, ?)""",
            (class_name, field_name, field_type, field_size))
        self.conn.commit()
        return self.get_member_id(class_name, field_name)

    def get_member_id(self, class_name: str, field_name: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT id FROM struct_members WHERE class_name = ? AND field_name = ?",
            (class_name, field_name)).fetchone()
        return row['id'] if row else None

    # -- Ground truth ingestion from eqgame.h --

    def ingest_eqgame_h(self, binary_id: int, header_path: str):
        """Parse eqgame.h and store function addresses."""
        with open(header_path) as f:
            content = f.read()

        count = 0
        for m in re.finditer(r'^#define\s+(\S+)_x\s+(0x[0-9a-fA-F]+)', content, re.MULTILINE):
            func_name = m.group(1)
            addr = int(m.group(2), 16)
            self.conn.execute(
                """INSERT OR REPLACE INTO function_identities (binary_id, func_name, func_addr)
                   VALUES (?, ?, ?)""",
                (binary_id, func_name, addr))
            count += 1

        # Also grab __ClientDate
        cd_match = re.search(r'__ClientDate\s+(\d+)', content)
        if cd_match:
            self.conn.execute(
                "UPDATE binaries SET client_date = ? WHERE id = ?",
                (int(cd_match.group(1)), binary_id))

        self.conn.commit()
        return count

    def ingest_struct_header(self, binary_id: int, header_path: str,
                             class_name: str, start_marker: str = None,
                             end_marker: str = None):
        """Parse a struct header (CXWnd.h etc) for member offsets.

        Looks for lines like: /*0x030*/ int  BottomOffset;
        between optional start/end markers.
        """
        with open(header_path) as f:
            content = f.read()

        if start_marker:
            idx = content.find(start_marker)
            if idx >= 0:
                content = content[idx:]
        if end_marker:
            idx = content.find(end_marker)
            if idx >= 0:
                content = content[:idx]

        member_re = re.compile(
            r'/\*0x([0-9a-fA-F]+)\*/\s+(\S+(?:\s*\*)?)\s+(\w+)\s*;')

        count = 0
        for m in member_re.finditer(content):
            offset = int(m.group(1), 16)
            field_type = m.group(2)
            field_name = m.group(3)

            if field_name.startswith('Pad'):
                continue

            member_id = self.ensure_member(class_name, field_name, field_type)
            self.conn.execute(
                """INSERT OR REPLACE INTO member_offsets
                   (binary_id, member_id, offset_val, confidence, source)
                   VALUES (?, ?, ?, 'GROUND_TRUTH', 'header_parse')""",
                (binary_id, member_id, offset))
            count += 1

        self.conn.commit()
        return count

    # -- Offset queries --

    def get_offset(self, binary_id: int, class_name: str,
                   field_name: str) -> Optional[int]:
        row = self.conn.execute("""
            SELECT mo.offset_val FROM member_offsets mo
            JOIN struct_members sm ON mo.member_id = sm.id
            WHERE mo.binary_id = ? AND sm.class_name = ? AND sm.field_name = ?
        """, (binary_id, class_name, field_name)).fetchone()
        return row['offset_val'] if row else None

    def get_member_at_offset(self, binary_id: int, class_name: str,
                             offset: int) -> Optional[dict]:
        row = self.conn.execute("""
            SELECT sm.field_name, sm.field_type, mo.confidence, mo.source
            FROM member_offsets mo
            JOIN struct_members sm ON mo.member_id = sm.id
            WHERE mo.binary_id = ? AND sm.class_name = ? AND mo.offset_val = ?
        """, (binary_id, class_name, offset)).fetchone()
        return dict(row) if row else None

    def get_member_history(self, class_name: str, field_name: str) -> list:
        rows = self.conn.execute("""
            SELECT b.build_date, b.server, mo.offset_val, mo.confidence, mo.source
            FROM member_offsets mo
            JOIN struct_members sm ON mo.member_id = sm.id
            JOIN binaries b ON mo.binary_id = b.id
            WHERE sm.class_name = ? AND sm.field_name = ?
            ORDER BY b.build_date
        """, (class_name, field_name)).fetchall()
        return [dict(r) for r in rows]

    # -- Evidence records --

    def add_evidence(self, binary_id: int, class_name: str, field_name: str,
                     func_name: str, func_addr: int, evidence_type: str,
                     decompile_line: str = None, confidence: str = 'HIGH'):
        member_id = self.ensure_member(class_name, field_name)

        # Ensure function exists
        self.conn.execute(
            """INSERT OR IGNORE INTO function_identities (binary_id, func_name, func_addr)
               VALUES (?, ?, ?)""",
            (binary_id, func_name, func_addr))
        self.conn.commit()

        func_row = self.conn.execute(
            "SELECT id FROM function_identities WHERE binary_id = ? AND func_name = ?",
            (binary_id, func_name)).fetchone()

        self.conn.execute(
            """INSERT INTO evidence_records
               (binary_id, member_id, func_id, evidence_type, decompile_line, confidence)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (binary_id, member_id, func_row['id'], evidence_type, decompile_line, confidence))
        self.conn.commit()

    def get_evidence(self, class_name: str, field_name: str) -> list:
        rows = self.conn.execute("""
            SELECT b.build_date, fi.func_name, fi.func_addr,
                   er.evidence_type, er.decompile_line, er.confidence
            FROM evidence_records er
            JOIN struct_members sm ON er.member_id = sm.id
            JOIN function_identities fi ON er.func_id = fi.id
            JOIN binaries b ON er.binary_id = b.id
            WHERE sm.class_name = ? AND sm.field_name = ?
            ORDER BY b.build_date
        """, (class_name, field_name)).fetchall()
        return [dict(r) for r in rows]

    # -- Function identity --

    def add_function(self, binary_id: int, func_name: str, func_addr: int) -> int:
        self.conn.execute(
            """INSERT OR REPLACE INTO function_identities (binary_id, func_name, func_addr)
               VALUES (?, ?, ?)""",
            (binary_id, func_name, func_addr))
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM function_identities WHERE binary_id = ? AND func_name = ?",
            (binary_id, func_name)).fetchone()
        return row['id']

    def get_function_addr(self, binary_id: int, func_name: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT func_addr FROM function_identities WHERE binary_id = ? AND func_name = ?",
            (binary_id, func_name)).fetchone()
        return row['func_addr'] if row else None

    # -- BinDiff data --

    def ingest_bindiff(self, old_binary_id: int, new_binary_id: int,
                       bindiff_db_path: str) -> int:
        """Import function matches from a BinDiff .BinDiff SQLite file."""
        bd_conn = sqlite3.connect(bindiff_db_path)
        bd_conn.row_factory = sqlite3.Row

        rows = bd_conn.execute("""
            SELECT address1, address2, similarity
            FROM function
            WHERE similarity > 0.3
        """).fetchall()

        count = 0
        for row in rows:
            self.conn.execute(
                """INSERT OR IGNORE INTO bindiff_matches
                   (old_binary, new_binary, old_addr, new_addr, similarity)
                   VALUES (?, ?, ?, ?, ?)""",
                (old_binary_id, new_binary_id,
                 row['address1'], row['address2'], row['similarity']))
            count += 1

        bd_conn.close()
        self.conn.commit()
        return count

    def translate_address(self, old_binary_id: int, new_binary_id: int,
                          old_addr: int) -> Optional[int]:
        row = self.conn.execute("""
            SELECT new_addr FROM bindiff_matches
            WHERE old_binary = ? AND new_binary = ? AND old_addr = ?
        """, (old_binary_id, new_binary_id, old_addr)).fetchone()
        return row['new_addr'] if row else None

    # -- Patch day helpers --

    def find_identifying_functions(self, class_name: str,
                                   field_name: str) -> list:
        """Find functions that consistently identify a field across builds.

        Returns functions ranked by how many builds they appear in with
        HIGH confidence evidence.
        """
        rows = self.conn.execute("""
            SELECT fi.func_name, er.evidence_type, COUNT(DISTINCT b.id) as build_count,
                   GROUP_CONCAT(DISTINCT b.build_date) as builds
            FROM evidence_records er
            JOIN struct_members sm ON er.member_id = sm.id
            JOIN function_identities fi ON er.func_id = fi.id
            JOIN binaries b ON er.binary_id = b.id
            WHERE sm.class_name = ? AND sm.field_name = ?
              AND er.confidence = 'HIGH'
            GROUP BY fi.func_name, er.evidence_type
            ORDER BY build_count DESC
        """, (class_name, field_name)).fetchall()
        return [dict(r) for r in rows]

    def get_all_members(self, class_name: str, binary_id: int) -> list:
        """Get all known member offsets for a class in a specific build."""
        rows = self.conn.execute("""
            SELECT sm.field_name, sm.field_type, mo.offset_val, mo.confidence, mo.source
            FROM member_offsets mo
            JOIN struct_members sm ON mo.member_id = sm.id
            WHERE sm.class_name = ? AND mo.binary_id = ?
            ORDER BY mo.offset_val
        """, (class_name, binary_id)).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        """Quick summary stats."""
        return {
            'binaries': self.conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0],
            'members': self.conn.execute("SELECT COUNT(*) FROM struct_members").fetchone()[0],
            'offsets': self.conn.execute("SELECT COUNT(*) FROM member_offsets").fetchone()[0],
            'functions': self.conn.execute("SELECT COUNT(*) FROM function_identities").fetchone()[0],
            'evidence': self.conn.execute("SELECT COUNT(*) FROM evidence_records").fetchone()[0],
            'bindiff': self.conn.execute("SELECT COUNT(*) FROM bindiff_matches").fetchone()[0],
        }


if __name__ == '__main__':
    import sys
    db = EQXrefDB()
    if len(sys.argv) > 1 and sys.argv[1] == 'stats':
        for k, v in db.stats().items():
            print(f"  {k}: {v}")
    else:
        print(f"Database: {db.db_path}")
        print("Run with 'stats' to see counts.")
    db.close()
