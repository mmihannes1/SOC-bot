import csv
from typing import List, Dict


def parse_dns_log(file_path: str) -> List[Dict]:
    indicators = []
    with open(file_path, "r") as f:
        # Find the #fields line to get headers
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split()[1:]  # skip "#fields"
                break
        # Prepare a generator for non-comment lines
        rows = (l for l in f if not l.startswith("#") and l.strip())
        reader = csv.DictReader(rows, fieldnames=headers, delimiter="\t")
        for row in reader:
            if row.get("query") and not row["query"].endswith(".arpa"):
                indicators.append(
                    {
                        "indicator": row["query"],
                        "type": "domain",
                        "src_ip": row.get("id.orig_h", ""),
                        "timestamp": row.get("ts", ""),
                    }
                )
    return indicators
