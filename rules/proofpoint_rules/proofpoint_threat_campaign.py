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
    threats_info = event.get("threatsInfoMap", [])
    if isinstance(threats_info, list):
        for threat in threats_info:
            if hasattr(threat, "get") and threat.get("campaignID"):
                campaign_id = threat.get("campaignID")
                break

    if campaign_id:
        return f"Proofpoint: Active Threat Campaign Detected - {campaign_id}"
    return f"Proofpoint: Active Threat Campaign - Email from {sender}"


def alert_context(event):
    threats = []
    campaign_ids = set()

    threats_info = event.get("threatsInfoMap", [])
    if not isinstance(threats_info, list):
        threats_info = []

    for threat in threats_info:
        if hasattr(threat, "get") and threat.get("campaignID"):
            campaign_ids.add(threat.get("campaignID", "<UNKNOWN_CAMPAIGN_ID>"))
            threats.append(
                {
                    "threat": threat.get("threat", "<UNKNOWN_THREAT>"),
                    "threatType": threat.get("threatType", "<UNKNOWN_THREAT_TYPE>"),
                    "classification": threat.get("classification", "<UNKNOWN_CLASSIFICATION>"),
                    "threatStatus": threat.get("threatStatus", "<UNKNOWN_THREAT_STATUS>"),
                    "campaignID": threat.get("campaignID", "<UNKNOWN_CAMPAIGN_ID>"),
                    "threatID": threat.get("threatID", "<UNKNOWN_THREAT_ID>"),
                }
            )

    return {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "campaignIDs": list(campaign_ids),
        "campaignCount": len(campaign_ids),
        "threats": threats,
        "malwareScore": event.get("malwareScore"),
        "phishScore": event.get("phishScore"),
        "quarantineFolder": event.get("quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"),
        "quarantineRule": event.get("quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"),
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
    }
