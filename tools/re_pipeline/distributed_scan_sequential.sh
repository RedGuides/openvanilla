#!/usr/bin/env bash
#
# distributed_scan_sequential.sh - Sequential-per-host rizin scanning
#
# Runs one build at a time per host (4 hosts = 4 concurrent scans).
# Each scan uses 48 workers internally, well within the 72 cores per host.
#
set -euo pipefail

HOSTS=(pvehost1 pvehost2 pvehost3 pvehost4)
SSH_OPTS="-o RemoteCommand=none"
BUILDS_DIR="/mnt/DEV/reverse-engineering/MQ-RE/eq-builds/live"
CACHE_DIR="/mnt/DEV/reverse-engineering/MQ-RE/data/disasm_cache"

# Get builds needing scan
BUILDS=()
for dir in "$BUILDS_DIR"/*/; do
    date=$(basename "$dir")
    if [ ! -d "$CACHE_DIR/$date" ] || [ $(find "$CACHE_DIR/$date" -name "*.asm" 2>/dev/null | wc -l) -lt 100 ]; then
        if [ -f "$dir/eqgame.exe" ] && [ -f "$dir/eqgame.h" ]; then
            BUILDS+=("$date")
        fi
    fi
done

echo "Builds needing scan: ${#BUILDS[@]}"

# Distribute round-robin
declare -A HOST_BUILDS
for i in "${!BUILDS[@]}"; do
    host_idx=$((i % ${#HOSTS[@]}))
    host="${HOSTS[$host_idx]}"
    HOST_BUILDS[$host]+="${BUILDS[$i]} "
done

for host in "${HOSTS[@]}"; do
    echo "$host: ${HOST_BUILDS[$host]:-none}"
done

# Copy scan script to each host
for host in "${HOSTS[@]}"; do
    ssh $SSH_OPTS "$host" "mkdir -p /tmp/eq_scan" 2>/dev/null

    cat << 'SCANNER' | ssh $SSH_OPTS "$host" "cat > /tmp/eq_scan/scan.py"
#!/usr/bin/env python3
import re, os, sys, subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed

def scan_func(exe, addr):
    try:
        result = subprocess.run(
            ["rizin", "-a", "x86", "-b", "64", "-q",
             "-c", f"af @ {addr}; pdf @ {addr}",
             exe], capture_output=True, text=True, timeout=10)
        text = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
        return (addr, text)
    except:
        return (addr, None)

def main():
    build_date = sys.argv[1]
    exe = f"/tmp/eq_scan/{build_date}/eqgame.exe"
    header = f"/tmp/eq_scan/{build_date}/eqgame.h"
    out_dir = f"/tmp/eq_scan/{build_date}/disasm"
    os.makedirs(out_dir, exist_ok=True)

    funcs = {}
    with open(header) as f:
        for line in f:
            m = re.match(r'#define\s+(\S+)_x\s+(0x[0-9a-fA-F]+)', line.strip())
            if m:
                funcs[m.group(1)] = m.group(2)

    print(f"Scanning {len(funcs)} functions for {build_date}")

    with ProcessPoolExecutor(max_workers=48) as executor:
        futures = {executor.submit(scan_func, exe, addr): name for name, addr in funcs.items()}
        done = 0
        for future in as_completed(futures):
            name = futures[future]
            addr, text = future.result()
            done += 1
            if text and len(text) > 10:
                with open(f"{out_dir}/{name}.asm", 'w') as f:
                    f.write(text)
            if done % 50 == 0:
                print(f"  {done}/{len(funcs)}...")

    print(f"Done: {build_date}")

if __name__ == '__main__':
    main()
SCANNER
done

# For each host, create a wrapper that runs builds SEQUENTIALLY
for host in "${HOSTS[@]}"; do
    builds="${HOST_BUILDS[$host]:-}"
    if [ -z "$builds" ]; then
        continue
    fi

    echo ""
    echo "=== Setting up $host ==="

    # Copy all build files first
    for date in $builds; do
        echo "  Copying $date to $host..."
        ssh $SSH_OPTS "$host" "mkdir -p /tmp/eq_scan/$date"
        scp -q "$BUILDS_DIR/$date/eqgame.exe" "$host:/tmp/eq_scan/$date/"
        scp -q "$BUILDS_DIR/$date/eqgame.h" "$host:/tmp/eq_scan/$date/"
    done

    # Create sequential runner script
    build_list=""
    for date in $builds; do
        build_list+="$date "
    done

    ssh $SSH_OPTS "$host" "cat > /tmp/eq_scan/run_all.sh" << RUNNER
#!/bin/bash
for date in $build_list; do
    echo "[\$(date '+%H:%M:%S')] Starting \$date"
    python3 /tmp/eq_scan/scan.py \$date >> /tmp/eq_scan/\${date}.log 2>&1
    echo "[\$(date '+%H:%M:%S')] Finished \$date"
done
echo "ALL DONE on \$(hostname)"
RUNNER

    # Launch sequential runner in background
    echo "  Launching sequential scan on $host..."
    ssh $SSH_OPTS "$host" "nohup bash /tmp/eq_scan/run_all.sh > /tmp/eq_scan/master.log 2>&1 &" &
done

wait

echo ""
echo "All hosts launched (sequential per host). Monitor with:"
echo "  for h in pvehost{1..4}; do echo \"=== \$h ===\"; ssh $SSH_OPTS \$h 'cat /tmp/eq_scan/master.log 2>/dev/null | tail -5'; done"
echo ""
echo "When done, collect results with:"
echo "  for h in pvehost{1..4}; do"
echo "    for d in \$(ssh $SSH_OPTS \$h 'ls -d /tmp/eq_scan/20*/disasm 2>/dev/null'); do"
echo "      date=\$(basename \$(dirname \$d))"
echo "      mkdir -p $CACHE_DIR/\$date"
echo "      rsync -a \$h:\$d/ $CACHE_DIR/\$date/"
echo "    done"
echo "  done"
