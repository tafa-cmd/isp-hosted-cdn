#!/usr/bin/env python3
import argparse, json
from collections import defaultdict, Counter

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)

def chao2(incidence: Counter) -> float:
    S = len(incidence)
    Q1 = sum(1 for c in incidence.values() if c == 1)
    Q2 = sum(1 for c in incidence.values() if c == 2)
    if Q2 == 0:
        return float(S + (Q1 * (Q1 - 1)) / 2) if Q1 > 1 else float(S)
    return float(S + (Q1 * Q1) / (2 * Q2))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--out-ips", default="unique_ipv4.txt",
                    help="Output file for unique IPv4 addresses")
    args = ap.parse_args()

    resolver2ips = defaultdict(set)
    total = 0
    errors = 0

    for rec in load_jsonl(args.infile):
        total += 1
        if rec.get("error"):
            errors += 1
            continue
        r = rec["resolver"]
        for ip in rec.get("a", []):
            resolver2ips[r].add(ip)

    resolvers = list(resolver2ips.keys())

    # Accumulation curve
    seen = set()
    curve = []
    for r in sorted(resolvers):
        seen |= resolver2ips[r]
        curve.append(len(seen))

    # Incidence counts
    incidence = Counter()
    for r in resolvers:
        for ip in resolver2ips[r]:
            incidence[ip] += 1

    # Save unique IPv4
    unique_ips = sorted(incidence.keys())
    with open(args.out_ips, "w", encoding="utf-8") as f:
        for ip in unique_ips:
            f.write(ip + "\n")

    print("File:", args.infile)
    print("Resolvers with any answers:", len(resolvers))
    print("Total records:", total, "Errors:", errors)
    print("Unique IPv4 observed:", len(unique_ips))
    print("Chao2 estimated total unique IPv4:", round(chao2(incidence), 2))
    print("Last 10 points of saturation curve:", curve[-10:])
    print("Saved unique IPv4 to:", args.out_ips)

if __name__ == "__main__":
    main()

