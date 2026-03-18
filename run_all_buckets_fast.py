#!/usr/bin/env python3
import argparse, json, time, socket
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from collections import defaultdict
from itertools import product
import dns.message, dns.query, dns.flags, dns.rdatatype

def load_lines(path):
    out=[]
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            s=line.strip()
            if s and not s.startswith("#"):
                out.append(s)
    return out

def is_ipv4(addr: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except OSError:
        return False

def query_A(qname, resolver, timeout):
    msg = dns.message.make_query(qname, "A", want_dnssec=False)
    msg.flags |= dns.flags.RD
    try:
        resp = dns.query.udp(msg, resolver, timeout=timeout)
    except dns.message.Truncated:
        resp = dns.query.tcp(msg, resolver, timeout=timeout)

    want = dns.rdatatype.from_text("A")
    out=[]
    for rrset in resp.answer:
        if rrset.rdtype == want:
            for rdata in rrset:
                out.append(rdata.to_text().strip())
    return [ip for ip in out if is_ipv4(ip)]

def do_one(resolver, bucket, timeout):
    return {
        "ts": time.time(),
        "resolver": resolver,
        "bucket": bucket,
        "a": [],
        "error": None
    } | (lambda: {"a": query_A(bucket, resolver, timeout)} )()

def safe_do_one(resolver, bucket, timeout):
    rec = {"ts": time.time(), "resolver": resolver, "bucket": bucket, "a": [], "error": None}
    try:
        rec["a"] = query_A(bucket, resolver, timeout)
    except Exception as e:
        rec["error"] = f"{type(e).__name__}:{e}"
    return rec

def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def is_timeout_like(error: str) -> bool:
    if not error:
        return False
    etype = error.split(":", 1)[0]
    if etype in {"Timeout", "LifetimeTimeout", "TimeoutError", "NoNameservers"}:
        return True
    low = error.lower()
    return ("timed out" in low) or ("timeout" in low)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--buckets", required=True)
    ap.add_argument("--resolvers", required=True)
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--workers", type=int, default=250)
    ap.add_argument("--in-flight", type=int, default=1000,
                    help="Max number of submitted-but-not-yet-written tasks.")
    ap.add_argument("--progress-every", type=int, default=20000,
                    help="Print status every N processed pairs (completed + skipped).")
    ap.add_argument("--progress-seconds", type=float, default=30.0,
                    help="Also print status at least every N seconds.")
    ap.add_argument("--max-consecutive-timeouts", type=int, default=0,
                    help="If >0, skip remaining buckets for resolvers after this many timeout-like errors in a row.")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    buckets = [b.rstrip(".") + "." for b in load_lines(args.buckets)]
    resolvers = load_lines(args.resolvers)

    total = len(buckets) * len(resolvers)
    done = 0
    skipped = 0
    start_ts = time.time()
    next_progress_mark = max(1, args.progress_every)
    last_progress_ts = start_ts
    exhausted = False
    consecutive_timeouts = defaultdict(int)
    disabled_resolvers = set()

    def print_progress(force=False):
        nonlocal next_progress_mark, last_progress_ts
        processed = done + skipped
        now = time.time()
        if not force and processed < next_progress_mark and (now - last_progress_ts) < args.progress_seconds:
            return

        elapsed = now - start_ts
        rate = (processed / elapsed) if elapsed > 0 else 0.0
        remain = max(0, total - processed)
        eta = (remain / rate) if rate > 0 else float("inf")
        eta_txt = fmt_duration(eta) if eta != float("inf") else "unknown"
        print(
            f"progress {processed}/{total} "
            f"(done={done}, skipped={skipped}, disabled={len(disabled_resolvers)}) "
            f"rate={rate:.1f}/s elapsed={fmt_duration(elapsed)} eta={eta_txt}"
        )
        while next_progress_mark <= processed:
            next_progress_mark += max(1, args.progress_every)
        last_progress_ts = now

    with open(args.out, "w", encoding="utf-8") as out:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            pair_iter = product(resolvers, buckets)
            in_flight = set()
            fut_to_resolver = {}

            def refill():
                nonlocal skipped, exhausted
                while not exhausted and len(in_flight) < max_in_flight:
                    try:
                        r, b = next(pair_iter)
                    except StopIteration:
                        exhausted = True
                        break
                    if r in disabled_resolvers:
                        skipped += 1
                        continue
                    fut = ex.submit(safe_do_one, r, b, args.timeout)
                    in_flight.add(fut)
                    fut_to_resolver[fut] = r

            max_in_flight = max(args.workers, args.in_flight)
            refill()

            while in_flight or not exhausted:
                if not in_flight:
                    refill()
                    if not in_flight and exhausted:
                        break

                done_set, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                for fut in done_set:
                    in_flight.discard(fut)
                    resolver = fut_to_resolver.pop(fut, None)
                    if fut.cancelled():
                        skipped += 1
                        continue

                    rec = fut.result()
                    out.write(json.dumps(rec) + "\n")
                    done += 1
                    if args.max_consecutive_timeouts > 0 and resolver is not None:
                        if is_timeout_like(rec.get("error")):
                            consecutive_timeouts[resolver] += 1
                            if (
                                resolver not in disabled_resolvers
                                and consecutive_timeouts[resolver] >= args.max_consecutive_timeouts
                            ):
                                disabled_resolvers.add(resolver)
                                cancelled = 0
                                for pending in list(in_flight):
                                    if fut_to_resolver.get(pending) == resolver and pending.cancel():
                                        in_flight.discard(pending)
                                        fut_to_resolver.pop(pending, None)
                                        skipped += 1
                                        cancelled += 1
                                print(
                                    f"disable resolver {resolver} after "
                                    f"{consecutive_timeouts[resolver]} timeout-like errors "
                                    f"(cancelled={cancelled})"
                                )
                        else:
                            consecutive_timeouts[resolver] = 0

                    print_progress()

                refill()

    print_progress(force=True)
    print("done:", args.out)

if __name__ == "__main__":
    main()
