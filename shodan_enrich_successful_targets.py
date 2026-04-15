#!/usr/bin/env python3
"""
Enrich successful RIPE Atlas destination IPs with Shodan 443/TLS metadata.

Input:
  - CSV with a column named target_ip (preferred)
  - CSV with a column named ip
  - TXT with one IP per line

Output:
  - CSV with one row per input IP
  - JSONL with the same extracted rows

Auth:
  export SHODAN_API_KEY="..."
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    import shodan
except ImportError:
    shodan = None

HOST_TIMEOUT = 30


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enrich successful target IPs with Shodan 443/TLS metadata."
    )
    parser.add_argument("input_path", help="Input CSV or TXT of successful target IPs.")
    parser.add_argument("--out-csv", required=True, help="Output CSV path.")
    parser.add_argument("--out-jsonl", required=True, help="Output JSONL path.")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent Shodan lookups.")
    return parser


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def read_ips(path: Path) -> list[str]:
    ips: list[str] = []

    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames or []
            candidate_field = "target_ip" if "target_ip" in fieldnames else "ip"
            if candidate_field not in fieldnames:
                raise ValueError("CSV input must contain a 'target_ip' or 'ip' column")
            for row in reader:
                raw_ip = (row.get(candidate_field) or "").strip()
                if raw_ip and is_ip(raw_ip):
                    ips.append(normalize_ip(raw_ip))
    else:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw_ip = line.strip()
                if raw_ip and is_ip(raw_ip):
                    ips.append(normalize_ip(raw_ip))

    seen: set[str] = set()
    deduped: list[str] = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        deduped.append(ip)
    return deduped


def get_client(api_key: str) -> Any:
    if shodan is None:
        raise RuntimeError(
            "The 'shodan' package is not installed. Install it with 'python3 -m pip install shodan'."
        )
    client = shodan.Shodan(api_key)
    # The library uses requests internally; configure a timeout attribute when present.
    if hasattr(client, "_request_timeout"):
        client._request_timeout = HOST_TIMEOUT
    return client


def fetch_host(client: Any, ip: str) -> dict[str, Any]:
    return client.host(ip)


def find_443_service(host_json: dict[str, Any]) -> dict[str, Any] | None:
    for entry in host_json.get("data", []) or []:
        if entry.get("port") == 443:
            return entry
    return None


def first_present_string(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def coerce_san(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def extract_san(service: dict[str, Any]) -> list[str]:
    ssl = service.get("ssl") or {}
    cert = ssl.get("cert") or {}
    extensions = cert.get("extensions") or {}
    subject_alt = extensions.get("subject_alt_name") or {}

    candidates = [
        cert.get("subjectAltName"),
        cert.get("subjectaltname"),
        cert.get("alt_names"),
        extensions.get("subjectAltName"),
        subject_alt.get("dns_names"),
        subject_alt.get("ip_addresses"),
    ]

    for candidate in candidates:
        san_values = coerce_san(candidate)
        if san_values:
            return san_values
    return []


def extract_whois_name(host_json: dict[str, Any], service: dict[str, Any]) -> str:
    return first_present_string(
        (host_json.get("whois") or {}).get("organization"),
        host_json.get("org"),
        service.get("org"),
        host_json.get("isp"),
    )


def enrich_ip(api_key: str, ip: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "target_ip": ip,
        "status": "ok",
        "port_443_present": "False",
        "whois_name": "none",
        "san": "none",
        "country": "none",
    }

    try:
        client = get_client(api_key)
        host_json = fetch_host(client, ip)
    except RuntimeError as exc:
        row["status"] = "client_error"
        row["error"] = str(exc)
        return row
    except Exception as exc:
        if shodan is not None and isinstance(exc, shodan.APIError):
            row["status"] = "host_api_error"
            row["error"] = str(exc)
            return row
        row["status"] = "host_http_error"
        row["error"] = str(exc)
        return row

    service_443 = find_443_service(host_json)
    if service_443 is None:
        row["status"] = "no_port_443"
        return row

    san_values = extract_san(service_443)
    country = first_present_string(
        ((service_443.get("location") or {}).get("country_name")),
        host_json.get("country_name"),
        host_json.get("country_code"),
    )
    row.update(
        {
            "port_443_present": "True",
            "whois_name": extract_whois_name(host_json, service_443) or "none",
            "san": ";".join(san_values) if san_values else "none",
            "country": country or "none",
            "port_443_org": first_present_string(service_443.get("org"), host_json.get("org")) or "none",
            "port_443_hostnames": ";".join(service_443.get("hostnames") or []) or "none",
        }
    )
    return row


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames: set[str] = set()
    for row in rows:
        fieldnames.update(row.keys())

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted(fieldnames))
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def main() -> int:
    args = build_parser().parse_args()
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("Set SHODAN_API_KEY in the environment.")
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")
    if shodan is None:
        raise SystemExit(
            "The 'shodan' package is not installed. Install it with 'python3 -m pip install shodan'."
        )

    input_path = Path(args.input_path).expanduser().resolve()
    ips = read_ips(input_path)
    rows: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(enrich_ip, api_key, ip): ip for ip in ips
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                rows.append(future.result())
            except Exception as exc:
                rows.append(
                    {
                        "target_ip": ip,
                        "status": "worker_error",
                        "port_443_present": "False",
                        "whois_name": "none",
                        "san": "none",
                        "country": "none",
                        "error": str(exc),
                    }
                )

    rows.sort(key=lambda row: row.get("target_ip") or "")

    out_csv = Path(args.out_csv).expanduser().resolve()
    out_jsonl = Path(args.out_jsonl).expanduser().resolve()
    write_csv(out_csv, rows)
    write_jsonl(out_jsonl, rows)

    print(
        json.dumps(
            {
                "input_path": str(input_path),
                "out_csv": str(out_csv),
                "out_jsonl": str(out_jsonl),
                "rows_written": len(rows),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
