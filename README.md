```
python3 run_all_buckets_fast.py   --buckets unique_akamai_cnames.txt   --resolvers resolvers_validated_final.txt   --workers 400   --in-flight 4000   --timeout 1.0   --max-consecutive-timeouts 5   --progress-every 20000   --progress-seconds 15   --out out_all_buckets_r28000.jsonl
```

```
python3 analyze_all_buckets_a.py --in out_all_buckets_r28000.jsonl --out-ips unique_ipv4_r28000.txt
```
