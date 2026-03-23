#!/usr/bin/env python3
"""Build a JSON catalog from all panther-analysis YAML detection files."""

import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SEARCH_DIRS = ["rules", "policies", "queries", "correlation_rules", "data_models", "global_helpers"]
OUTPUT = Path(__file__).parent / "catalog.json"
MITRE_LOOKUP = Path(__file__).parent / "mitre_lookup.json"


def load_mitre_lookup():
    if MITRE_LOOKUP.exists():
        with open(MITRE_LOOKUP) as f:
            return json.load(f)
    return {"tactics": {}, "techniques": {}}


def main():
    mitre = load_mitre_lookup()
    tactics_map = mitre["tactics"]
    # techniques_map values are now objects with 'name', 'tactics', 'is_sub'
    techniques_map = mitre["techniques"]

    content = []
    for search_dir in SEARCH_DIRS:
        dirpath = REPO_ROOT / search_dir
        if not dirpath.exists():
            continue
        for yml_file in sorted(dirpath.rglob("*.yml")):
            try:
                with open(yml_file) as f:
                    data = yaml.safe_load(f)
                if not data or not isinstance(data, dict):
                    continue
                if "AnalysisType" not in data:
                    continue

                reports = data.get("Reports") or {}
                raw_mitre = reports.get("MITRE ATT&CK") or []

                # Split into tactics and techniques with friendly names
                item_tactics = []
                item_techniques = []
                mitre_raw = []
                for entry in raw_mitre:
                    parts = entry.split(":")
                    if len(parts) == 2:
                        tactic_id, tech_id = parts
                        tactic_name = tactics_map.get(tactic_id, tactic_id)
                        tech_info = techniques_map.get(tech_id)
                        tech_name = tech_info["name"] if isinstance(tech_info, dict) else (tech_info if tech_info else tech_id)
                        tactic_label = f"[{tactic_id}] {tactic_name}"
                        tech_label = f"[{tech_id}] {tech_name}"
                        if tactic_label not in item_tactics:
                            item_tactics.append(tactic_label)
                        if tech_label not in item_techniques:
                            item_techniques.append(tech_label)
                        mitre_raw.append(entry)

                item = {
                    "id": data.get("RuleID") or data.get("PolicyID") or data.get("QueryName") or data.get("DataModelID") or data.get("GlobalID") or "unknown",
                    "displayName": data.get("DisplayName") or data.get("QueryName") or data.get("DataModelID") or data.get("GlobalID") or "",
                    "description": data.get("Description", ""),
                    "type": data.get("AnalysisType", ""),
                    "enabled": bool(data.get("Enabled", False)),
                    "severity": (data.get("Severity") or "").upper(),
                    "tags": data.get("Tags") or [],
                    "logTypes": data.get("LogTypes") or data.get("ResourceTypes") or [],
                    "mitreRaw": mitre_raw,
                    "mitreTactics": item_tactics,
                    "mitreTechniques": item_techniques,
                    "reference": data.get("Reference", ""),
                    "runbook": data.get("Runbook", ""),
                    "filepath": str(yml_file.relative_to(REPO_ROOT)),
                    "dedupMinutes": data.get("DedupPeriodMinutes"),
                    "threshold": data.get("Threshold"),
                    "testCount": len(data.get("Tests") or []),
                }
                content.append(item)
            except Exception as e:
                print(f"  Warning: skipping {yml_file}: {e}")
                continue

    with open(OUTPUT, "w") as f:
        json.dump(content, f, indent=2)

    print(f"  Built catalog: {len(content)} detections -> {OUTPUT}")


if __name__ == "__main__":
    main()
