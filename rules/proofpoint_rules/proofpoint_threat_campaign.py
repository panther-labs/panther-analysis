from panther_proofpoint_helpers import extract_threats


def rule(event):
    # Check if any threats have a campaign ID
    for threat in event.get("threatsInfoMap", []):
        if threat.get("campaignID") and threat.get("threatStatus") == "active":
            return True

    return False


def severity(event):
    malware_score = event.get("malwareScore", 0)
    phish_score = event.get("phishScore", 0)

    if malware_score >= 90 or phish_score >= 90:
        return "CRITICAL"
    if malware_score >= 70 or phish_score >= 70:
        return "HIGH"
    return "DEFAULT"


def title(event):
    sender = event.get("sender", "<UNKNOWN_SENDER>")

    # Get campaign ID from first threat with one
    campaign_id = None
    for threat in event.get("threatsInfoMap", []):
        if threat.get("campaignID"):
            campaign_id = threat.get("campaignID")
            break

    if campaign_id:
        return f"Proofpoint: Active Threat Campaign Detected - {campaign_id}"
    return f"Proofpoint: Active Threat Campaign - Email from {sender}"


def alert_context(event):
    # Extract all threats using the helper
    all_threats = extract_threats(event)

    # Filter to only threats with campaign IDs
    campaign_threats = [t for t in all_threats if "campaignID" in t]
    campaign_ids = set(t.get("campaignID") for t in campaign_threats if t.get("campaignID"))

    return {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
        "quarantineFolder": event.get("quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"),
        "quarantineRule": event.get("quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"),
        "malwareScore": event.get("malwareScore", 0),
        "phishScore": event.get("phishScore", 0),
        "campaignIDs": list(campaign_ids),
        "campaignCount": len(campaign_ids),
        "threats": campaign_threats,
    }
