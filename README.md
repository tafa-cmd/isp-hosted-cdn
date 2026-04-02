```
python3 run_all_buckets_fast.py   --buckets unique_akamai_cnames.txt   --resolvers resolvers_validated_final.txt   --workers 400   --in-flight 4000   --timeout 1.0   --max-consecutive-timeouts 5   --progress-every 20000   --progress-seconds 15   --out out_all_buckets_r28000.jsonl
```

```
python3 analyze_all_buckets_a.py --in out_all_buckets_r28000.jsonl --out-ips unique_ipv4_r28000.txt
```

```
  python3 run_all_buckets_fast.py   --buckets unique_akamai_cnames.txt   --resolvers resolvers_validated.txt   --workers 400   --in-flight 2000   --timeout 1.0   --max-consecutive-timeouts 5   --progress-every 10000   --progress-seconds 15   --out out_all_buckets_r25000.jsonl
```


```
python3 -u "/home/odu/Desktop/extract_cnames/cdn_coverage_experiment.py" --domains "/home/odu/Desktop/extract_cnames/alibaba_domains_oct_2025_cname_resolved_cname.txt" --resolvers "/home/odu/Desktop/extract_cnames/resolvers_validated_final.txt" --ipinfo-location "/home/odu/Desktop/extract_cnames/ipinfo_location.csv" --ipinfo-asn "/home/odu/Desktop/extract_cnames/ipinfo_asn.csv" --initial-resolvers 5000 --step-resolvers 2000 --max-resolvers 15000 --target-cities 700 --target-prefixes 0 --stagnation-rounds 2 --out-prefix "/home/odu/Desktop/extract_cnames/alibaba_5k_plus2k"

```
