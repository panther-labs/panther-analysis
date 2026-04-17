#!/usr/bin/env python3
"""
Find experimental detection IDs that have processed events > 0
for more than 1 customer, where every customer has 0 matches and 0 errors.
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

CSV_PATH = Path(__file__).parent / "match-percentage.csv"


def main(csv_path: Path = CSV_PATH) -> None:
    # detection_id -> list of (customer, events, matches, errors)
    detections: dict[str, list[tuple[str, float, float, float]]] = defaultdict(list)

    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            detection_id = row["DETECTIONID"]
            customer = row["CUSTOMER_NAME"]

            events_raw = row[
                "SUM:PANTHER.EXPERIMENTAL_DETECTION.EVENTS{BASEDETECTIONVERSION:V3.100.0}.AS_COUNT()"
            ]
            matches_raw = row[
                "SUM:PANTHER.EXPERIMENTAL_DETECTION.MATCHES{BASEDETECTIONVERSION:V3.100.0}.AS_COUNT()"
            ]
            errors_raw = row[
                "SUM:PANTHER.EXPERIMENTAL_DETECTION.ERRORS{BASEDETECTIONVERSION:V3.100.0}.AS_COUNT()"
            ]

            events = float(events_raw) if events_raw not in ("", "null") else 0.0
            matches = float(matches_raw) if matches_raw not in ("", "null") else 0.0
            errors = float(errors_raw) if errors_raw not in ("", "null") else 0.0

            if events > 0:
                detections[detection_id].append((customer, events, matches, errors))

    results = []
    for detection_id, rows in detections.items():
        if (
            len(rows) > 1
            and all(matches == 0 for _, _, matches, _ in rows)
            and all(errors == 0 for _, _, _, errors in rows)
        ):
            total_events = sum(events for _, events, _, _ in rows)
            results.append((detection_id, rows, total_events))

    # Sort by number of customers desc, then total events desc
    results.sort(key=lambda x: (-len(x[1]), -x[2]))

    if not results:
        print("No detections found matching the criteria.")
        return

    print(f"Found {len(results)} detection(s) with events>0 for >1 customer, 0 matches, and 0 errors:\n")
    print(f"{'DETECTION ID':<50}  {'CUSTOMERS':>9}  {'TOTAL EVENTS':>14}")
    print("-" * 78)
    for detection_id, rows, total_events in results:
        print(f"{detection_id:<50}  {len(rows):>9}  {total_events:>14,.0f}")
        for customer, events, _, _ in sorted(rows, key=lambda r: -r[1]):
            print(f"  {'':48}  {customer:<20}  events={events:>12,.0f}")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else CSV_PATH
    main(path)
