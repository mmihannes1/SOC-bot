# File for parsing Zeek .logs

import csv
from typing import List, Dict


def parse_dns_log(file_path: str) -> List[Dict]:
    indicators = []

    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split()[1:]
                break

        rows = (l for l in f if not l.startswith("#") and l.strip())
        reader = csv.DictReader(rows, fieldnames=headers, delimiter="\t")
        for row in reader:
            if row.get("query") and not row["query"].endswith(".arpa"):
                indicators.append(
                    {
                        "uid": row.get("uid", ""),
                        "timestamp": row.get("ts", ""),
                        "src_ip": row.get("id.orig_h", ""),
                        "dns_server": row.get("id.resp_h", ""),
                        "query": row["query"],
                        "query_type": row.get("qtype_name", ""),
                        "rcode": row.get("rcode", ""),
                        "answer": row.get("answer", ""),
                        "ttl": row.get("ttl", ""),
                        "rejected": row.get("rejected", False),
                        "indicator_type": "domain",  # All queries are domain names
                        "indicator": row["query"],
                    }
                )
    return indicators


def parse_http_log(file_path: str) -> List[Dict]:
    indicators = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split()[1:]
                break

        rows = (l for l in f if not l.startswith("#") and l.strip())
        reader = csv.DictReader(rows, fieldnames=headers, delimiter="\t")
        for row in reader:
            if row.get("host") and not row["host"].endswith(".arpa"):
                indicators.append(
                    {
                        "uid": row.get("uid", ""),
                        "timestamp": row.get("ts", ""),
                        "src_ip": row.get("id.orig_h", ""),
                        "destination_ip": row.get("id.resp_h", ""),
                        "method": row.get("method", ""),
                        "uri": row.get("uri", ""),
                        "user_agent": row.get("user_agent", ""),
                        "referrer": row.get("referrer", ""),
                        "status_code": row.get("status_code", ""),
                        "request_size": row.get("request_body_len", ""),
                        "body_size": row.get("response_body_len", ""),
                        "indicator_type": "domain",
                        "indicator": row["host"],
                    }
                )
    return indicators


def parse_conn_log(file_path: str) -> List[Dict]:
    indicators = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split()[1:]
                break

        rows = (l for l in f if not l.startswith("#") and l.strip())
        reader = csv.DictReader(rows, fieldnames=headers, delimiter="\t")
        for row in reader:
            if row.get("id.orig_h") and not row["id.orig_h"].endswith(".arpa"):
                indicators.append(
                    {
                        "uid": row.get("uid", ""),
                        "timestamp": row.get("ts", ""),
                        "src_ip": row.get("id.orig_h", ""),
                        "destination_ip": row.get("id.resp_h", ""),
                        "protocol": row.get("proto", ""),
                        "service": row.get("service", ""),
                        "duration": row.get("duration", ""),
                        "orig_bytes": row.get("resp_bytes", ""),
                        "resp_bytes": row.get("resp_bytes", ""),
                        "indicator_type": "ip",
                        "indicator": row["id.orig_h"],
                    }
                )
    return indicators
