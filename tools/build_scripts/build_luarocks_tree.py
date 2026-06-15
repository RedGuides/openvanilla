"""Assemble MacroQuest's curated LuaRocks tree for bundling."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn
from zipfile import ZipFile

import yaml

LUA_VERSION = "5.1"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LUAROCKS_REPO = REPO_ROOT / "contrib" / "luarocks"
CURATED_MANIFEST_NAME = "mq_luarocks.yaml"

# e.g. #define LUAJIT_VERSION "LuaJIT 2.1.1774638290"
LUAJIT_VERSION_DEFINE_RE = re.compile(
    r'#define\s+LUAJIT_VERSION\s+"LuaJIT\s+([0-9][0-9A-Za-z.\-]*)"'
)

ARCH_ALL = "all"

# CLI arch -> (vcpkg triplet, rock arch suffix, PE machine)
ARCH_INFO = {
    "x64": ("x64-windows-static", "win32-x86_64", 0x8664),
    "x86": ("x86-windows-static", "win32-x86", 0x014C),
}


@dataclass(frozen=True)
class Rock:
    name: str
    files: list[str] = field(default_factory=list)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"ERROR: {message}")


def read_jit_version(header_path: Path) -> str:
    try:
        text = header_path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"could not read LuaJIT header {header_path}: {exc}")
    match = LUAJIT_VERSION_DEFINE_RE.search(text)
    if not match:
        fail(f"LUAJIT_VERSION define not found in {header_path}")
    return match.group(1)


def read_pe_machine(path: str) -> int | None:
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return None
            f.seek(0x3C)
            e_lfanew = int.from_bytes(f.read(4), "little")
            f.seek(e_lfanew)
            if f.read(4) != b"PE\0\0":
                return None
            return int.from_bytes(f.read(2), "little")
    except OSError:
        return None


def load_curated_rocks(manifest_path: Path) -> list[Rock]:
    try:
        text = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(
            f"could not read {manifest_path}: {exc}\n"
            "Is the contrib/luarocks submodule initialized? Run:\n"
            "    git submodule update --init contrib/luarocks"
        )
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not data:
        fail(f"{manifest_path} is not a usable curated manifest")

    rocks: list[Rock] = []
    for name, info in data.items():
        if not isinstance(info, dict):
            info = {}
        files = [str(f) for f in (info.get("files") or [])]
        rocks.append(Rock(name=str(name), files=files))
    return rocks


def describe_checkout(repo_path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    sha = result.stdout.strip()
    return sha if result.returncode == 0 and sha else "unknown"


def _version_key(ver_rev: str) -> tuple[tuple[int, ...], int]:
    version, _, revision = ver_rev.rpartition("-")
    if not version:
        version, revision = ver_rev, "0"
    version_parts = tuple(
        int(p) if p.isdigit() else -1 for p in version.split(".")
    )
    return version_parts, int(revision) if revision.isdigit() else -1


def resolve_rock(jit_dir: Path, name: str, target_arch: str) -> tuple[Path, str, str]:
    prefix = f"{name}-"
    candidates: list[tuple[str, str, Path]] = []
    for arch in (target_arch, ARCH_ALL):
        suffix = f".{arch}.rock"
        for path in jit_dir.glob(f"{prefix}*{suffix}"):
            ver_rev = path.name[len(prefix):-len(suffix)]
            # leading digit so "lua" doesn't match "lua-cjson-..."
            if ver_rev[:1].isdigit():
                candidates.append((ver_rev, arch, path))

    if not candidates:
        fail(f"{name} has no {target_arch} (or all-arch) rock in {jit_dir}")

    # newest version wins, target arch beats "all" on a tie
    candidates.sort(
        key=lambda c: (_version_key(c[0]), c[1] == target_arch), reverse=True
    )
    ver_rev, arch, path = candidates[0]
    return path, ver_rev, arch


def _deploy_dest(tree_path: str, rocks_record: str, rel: str) -> str:
    parts = [p for p in rel.split("/") if p and p != "."]
    if not parts:
        return rocks_record

    top = parts[0]
    if top == "lib" and len(parts) > 1:
        return os.path.join(tree_path, "lib", "lua", LUA_VERSION, *parts[1:])
    if top == "lua" and len(parts) > 1:
        return os.path.join(tree_path, "share", "lua", LUA_VERSION, *parts[1:])
    return os.path.join(rocks_record, *parts)


def deploy_rock(rock_path: str, tree_path: str, name: str, ver_rev: str) -> None:
    rocks_record = os.path.join(
        tree_path, "lib", "luarocks", f"rocks-{LUA_VERSION}", name, ver_rev
    )

    with ZipFile(rock_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = info.filename.replace("\\", "/")
            dest = _deploy_dest(tree_path, rocks_record, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(info) as source, open(dest, "wb") as target:
                shutil.copyfileobj(source, target)

    # marks the rock installed even if it shipped no record files
    os.makedirs(rocks_record, exist_ok=True)


def _file_in_tree(tree_path: str, rel: str) -> str:
    parts = rel.replace("\\", "/").split("/")
    return os.path.join(tree_path, "lib", "lua", LUA_VERSION, *parts)


def verify_rock(tree_path: str, rock: Rock, expected_machine: int) -> list[str]:
    problems: list[str] = []
    if not rock.files:
        recorded = os.path.join(tree_path, "lib", "luarocks", f"rocks-{LUA_VERSION}", rock.name)
        if not os.path.isdir(recorded):
            problems.append(f"{rock.name}: no rocks record directory at {recorded}")
        return problems

    for rel in rock.files:
        path = _file_in_tree(tree_path, rel)
        if not os.path.isfile(path):
            problems.append(f"{rock.name}: missing file {path}")
            continue
        if path.lower().endswith(".dll"):
            machine = read_pe_machine(path)
            if machine != expected_machine:
                problems.append(
                    f"{rock.name}: {path} has PE machine {machine:#06x}"
                    f" (expected {expected_machine:#06x})"
                    if machine is not None
                    else f"{rock.name}: {path} is not a valid PE file"
                )
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assemble MacroQuest's curated LuaRocks tree for bundling into VeryVanilla.zip."
    )
    parser.add_argument(
        "--mq-path", required=True,
        help="MQ release output directory (e.g. build/bin/Release)",
    )
    parser.add_argument(
        "--arch", required=True, choices=sorted(ARCH_INFO),
        help="Target architecture of this build",
    )
    parser.add_argument(
        "--luajit-header", type=Path, default=None,
        help="Path to the vcpkg-installed luajit.h (default: derived from --arch)",
    )
    parser.add_argument(
        "--luarocks-repo", type=Path, default=DEFAULT_LUAROCKS_REPO,
        help="Path to the pinned macroquest/luarocks checkout",
    )
    args = parser.parse_args()

    triplet, target_arch, expected_machine = ARCH_INFO[args.arch]
    header = args.luajit_header or (
        REPO_ROOT / "contrib" / "vcpkg" / "installed" / triplet / "include" / "luajit" / "luajit.h"
    )

    jit_version = read_jit_version(header)
    print(f"LuaJIT version: {jit_version} ({args.arch}, rocks arch {target_arch})")

    repo = args.luarocks_repo
    rocks = load_curated_rocks(repo / CURATED_MANIFEST_NAME)
    print(f"Rocks source: {repo} @ {describe_checkout(repo)}")
    print(f"Curated rocks: {', '.join(rock.name for rock in rocks)}")

    jit_dir = repo / jit_version
    if not jit_dir.is_dir():
        fail(
            f"{repo} has no rocks folder for LuaJIT {jit_version}; bump the "
            "contrib/luarocks submodule once upstream has published rocks for it"
        )

    mq_path = os.path.abspath(args.mq_path)
    if not os.path.isdir(mq_path):
        fail(f"--mq-path does not exist: {mq_path}")

    tree_path = os.path.join(mq_path, "modules", jit_version, "luarocks")
    if os.path.isdir(tree_path):
        print(f"Removing existing luarocks tree: {tree_path}")
        shutil.rmtree(tree_path)
    os.makedirs(tree_path)

    for rock in rocks:
        rock_path, ver_rev, arch = resolve_rock(jit_dir, rock.name, target_arch)
        deploy_rock(str(rock_path), tree_path, rock.name, ver_rev)
        print(f"Deployed {rock.name} {ver_rev} ({arch}) from {rock_path.name}")

    problems = [
        problem
        for rock in rocks
        for problem in verify_rock(tree_path, rock, expected_machine)
    ]
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        fail(f"luarocks tree verification failed with {len(problems)} problem(s)")

    file_count = sum(len(files) for _, _, files in os.walk(tree_path))
    print(f"OK: {len(rocks)} rock(s) verified in {tree_path} ({file_count} files)")


if __name__ == "__main__":
    main()
