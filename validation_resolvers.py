#!/usr/bin/env python3
import os
import subprocess
import tempfile
import time
import sys

INPUT_FILE = "open_resolvers.txt"
OUTPUT_FILE = "resolvers_validated_final.txt"
BATCH_SIZE = 50000
DNSVALIDATOR_CMD = "/usr/bin/dnsvalidator"   # change if needed


def count_lines(filename):
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


def format_time(seconds):
    if seconds < 0:
        seconds = 0
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def run_batch(batch_lines, batch_num):
    tmp_input = None
    tmp_output = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmp_in:
            tmp_in.writelines(batch_lines)
            tmp_input = tmp_in.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmp_out:
            tmp_output = tmp_out.name

        cmd = [
            DNSVALIDATOR_CMD,
            "-tL", tmp_input,
            "-o", tmp_output
        ]

        print(f"Starting batch {batch_num} with {len(batch_lines):,} resolvers...", flush=True)

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode != 0:
            print(f"[WARNING] Batch {batch_num} returned non-zero exit code: {result.returncode}", flush=True)

        written = 0
        if os.path.exists(tmp_output):
            with open(tmp_output, "r", encoding="utf-8", errors="ignore") as src, \
                 open(OUTPUT_FILE, "a", encoding="utf-8") as dst:
                for line in src:
                    dst.write(line)
                    written += 1

        print(f"Finished batch {batch_num} | Valid resolvers written: {written:,}", flush=True)

    except Exception as e:
        print(f"[ERROR] Batch {batch_num} failed: {e}", flush=True)

    finally:
        if tmp_input and os.path.exists(tmp_input):
            os.remove(tmp_input)
        if tmp_output and os.path.exists(tmp_output):
            os.remove(tmp_output)


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] Input file not found: {INPUT_FILE}", flush=True)
        sys.exit(1)

    if not os.path.exists(DNSVALIDATOR_CMD):
        print(f"[ERROR] dnsvalidator not found at: {DNSVALIDATOR_CMD}", flush=True)
        sys.exit(1)

    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    print("Counting total resolvers...", flush=True)
    total_lines = count_lines(INPUT_FILE)
    print(f"Total resolvers: {total_lines:,}", flush=True)

    start_time = time.time()
    processed = 0
    batch_num = 0
    batch_lines = []

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            batch_lines.append(line + "\n")

            if len(batch_lines) >= BATCH_SIZE:
                batch_num += 1
                batch_start_processed = processed
                run_batch(batch_lines, batch_num)
                processed += len(batch_lines)
                batch_lines = []

                elapsed = time.time() - start_time
                speed = processed / elapsed if elapsed > 0 else 0
                remaining = total_lines - processed
                eta = remaining / speed if speed > 0 else 0
                percent = (processed / total_lines * 100) if total_lines > 0 else 0

                print(
                    f"[Progress] {processed:,}/{total_lines:,} "
                    f"({percent:.2f}%) | "
                    f"Speed: {speed:,.2f} resolvers/sec | "
                    f"ETA: {format_time(eta)}",
                    flush=True
                )

        if batch_lines:
            batch_num += 1
            run_batch(batch_lines, batch_num)
            processed += len(batch_lines)

            elapsed = time.time() - start_time
            speed = processed / elapsed if elapsed > 0 else 0
            remaining = total_lines - processed
            eta = remaining / speed if speed > 0 else 0
            percent = (processed / total_lines * 100) if total_lines > 0 else 0

            print(
                f"[Progress] {processed:,}/{total_lines:,} "
                f"({percent:.2f}%) | "
                f"Speed: {speed:,.2f} resolvers/sec | "
                f"ETA: {format_time(eta)}",
                flush=True
            )

    total_elapsed = time.time() - start_time
    print("\nDone.", flush=True)
    print(f"Output saved to: {OUTPUT_FILE}", flush=True)
    print(f"Total runtime: {format_time(total_elapsed)}", flush=True)


if __name__ == "__main__":
    main()