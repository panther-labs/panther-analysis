import os
from typing import Any, Dict, List

import yaml

PACK_IDS_TO_TAG = {
    "PantherManaged.Auth0": "Auth0",
    "PantherManaged.Tines": "Tines",
    "PantherManaged.GCP.Audit": "GCP Audit",
    "PantherManaged.MultiSourceCorrelations": "Multi-source Correlations",
    "MispLookupTables": "Misp",
    "PantherManaged.Atlassian": "Atlassian",
    "Microsoft.Graph": "Microsoft Graph",
    "PantherManaged.Box": "Box",
    "PantherManaged.MongoDb": "MongoDB",
    "PantherManaged.Crowdstrike": "Crowdstrike",
    "PantherManaged.Netskope": "Netskope",
    "PantherManaged.CredentialSecurity": "Credential Security",
    "PantherManaged.PushSecurity": "Push Security",
    "PantherManaged.AzureAudit.Signin": "Azure Audit Signin",
    "PantherManaged.Tracebit": "Tracebit",
    "TorLookupTables": "Tor",
    "PantherManaged.Sublime": "Sublime",
    "PantherManaged.Slack": "Slack",
    "PantherManaged.CarbonBlack": "Carbon Black",
    "PantherManaged.CrowdstrikeEventStreams": "Crowdstrike Event Streams",
    "PantherManaged.OneLogin": "One Login",
    "PantherManaged.Tailscale": "Tailscale",
    "PantherManaged.SnowflakeStreaming": "Snowflake Streaming",
    "PantherManaged.Okta": "Okta",
    "PantherManaged.Wiz": "Wiz",
    "PantherManaged.AWS.CIS": "AWS CIS",
    "PantherManaged.Snyk": "Snyk",
    "PantherManaged.GitHub.Audit": "GitHub Audit",
    "PantherManaged.SentinelOne": "SentinelOne",
    "PantherManaged.AWS.Core": "AWS Core",
    "PantherManaged.Cloudflare": "Cloudflare",
    "PantherManaged.Orca.Alert": "Orca Alert",
    "PantherManaged.ThinkstCanary": "Thinkst Canary",
    "PantherManaged.Dropbox": "Dropbox",
    "PantherManaged.AWSDecoy": "AWS Decoy",
    "TrailDiscoverEnrichment": "Trail Discover Enrichment",
    "PantherManaged.Zscaler.ZIA": "Zscaler ZIA",
    "PantherManaged.Cisco.Umbrella": "Cisco Umbrella",
    "PantherManaged.Panther": "Panther",
    "IPInfo": "IP Info",
    "PantherManaged.Asana": "Asana",
    "PantherManaged.Zendesk.Audit": "Zendesk Audit",
    "PantherManaged.Anomalies": "Anomalies",
    "PantherManaged.Notion": "Notion",
    "PantherManaged.Salesforce": "Salesforce",
    "PantherManaged.Snowflake.Account_Usage": "Snowflake Account Usage",
    "PantherManaged.GCP.K8": "GCP K8",
    "PantherManaged.AppOmni": "AppOmni",
    "PantherManaged.Kubernetes.Core": "Kubernetes Core",
    "PantherManaged.Duo": "Duo",
    "PantherManaged.OSQuery": "OS Query",
    "PantherManaged.OnePassword": "One Password",
    "PantherManaged.ZoomDetections": "Zoom Detections",
    "PantherManaged.UniversalDetections": "Universal Detections",
    "PantherManaged.GSuite.Reports": "GSuite Reports",
    "PantherManaged.Gravitational.Teleport": "Gravitational Teleport",
}


def pack_id_to_tag(pack_id: str) -> str:
    return PACK_IDS_TO_TAG[pack_id]


def tag_list_prefix_spacing(analysis_contents: str) -> str:
    """Tags field has inconsistent spacing. Some have two spaces and some four."""
    start = analysis_contents.find("Tags:\n") + 6
    return " " * (analysis_contents.find("-", start) - start)


def analysis_id(item: Dict[str, Any]) -> str:
    match item["AnalysisType"].strip():
        case "rule" | "scheduled_rule" | "simple_rule" | "correlation_rule":
            return item["RuleID"]
        case "policy":
            return item["PolicyID"]
        case "scheduled_query" | "query" | "saved_query":
            return item["QueryName"]
        case "lookup_table":
            return item["LookupName"]
        case "pack":
            return item["PackID"]
        case "datamodel":
            return item["DataModelID"]
        case "global":
            return item["GlobalID"]
        case _:
            raise ValueError(f"Unknown analysis type: '{item['AnalysisType']}'")


def load_all_analysis_items() -> Dict[str, str]:
    analysis_items = {}
    for directory in [
        "rules",
        "policies",
        "queries",
        "correlation_rules",
        "lookup_tables",
        "data_models",
        "global_helpers",
    ]:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".yml"):
                    with open(os.path.join(root, file), "r") as f:
                        item = yaml.safe_load(f)
                        analysis_items[analysis_id(item)] = os.path.join(root, file)
    return analysis_items


def load_packs() -> List[Dict[str, Any]]:
    packs = []
    for root, _, files in os.walk("packs"):
        for file in files:
            if file.endswith(".yml"):
                with open(os.path.join(root, file), "r") as f:
                    packs.append(yaml.safe_load(f))
    return packs


def update_analysis_file_contents(analysis_file_path: str, tag: str) -> None:
    with open(analysis_file_path, "r") as f:
        analysis_file_contents = f.read()
    analysis_item = yaml.safe_load(analysis_file_contents)

    print(f"Attempting to update {analysis_file_path} with tag {tag}")

    if "Tags" in analysis_item and tag in analysis_item["Tags"]:
        print(f"  - Tag {tag} already exists")
        return

    if "Tags" in analysis_item:
        print("  - Prepending tag to existing Tags section")
        analysis_file_contents = analysis_file_contents.replace(
            "Tags:\n",
            f"Tags:\n{tag_list_prefix_spacing(analysis_file_contents)}- {tag}\n",
        )
    else:
        print("  - Adding new Tags section")
        if analysis_file_contents.endswith("\n"):
            analysis_file_contents = analysis_file_contents.rstrip("\n")
        analysis_file_contents = analysis_file_contents + (f"\nTags:\n  - {tag}\n")

    with open(analysis_file_path, "w") as f:
        f.write(analysis_file_contents)
        f.flush()


def packs_in_common() -> None:
    packs = load_packs()
    analysis_items = load_all_analysis_items()
    for pack in packs:
        for pack_item_id in pack["PackDefinition"]["IDs"]:
            analysis_file_path = analysis_items[pack_item_id]
            update_analysis_file_contents(
                analysis_file_path, pack_id_to_tag(pack["PackID"])
            )


if __name__ == "__main__":
    packs_in_common()
