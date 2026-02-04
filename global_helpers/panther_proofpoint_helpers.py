def extract_threats(event, include_threat_url=False):
    """
    Extract threat information from Proofpoint threatsInfoMap.

    Args:
        event: The Proofpoint event
        include_threat_url: Whether to include threatUrl in the threat dict

    Returns:
        List of threat dictionaries with standardized fields
    """
    threats = []
    for threat in event.get("threatsInfoMap", []):
        threat_dict = {
            "threat": threat.get("threat", "<UNKNOWN_THREAT>"),
            "threatType": threat.get("threatType", "<UNKNOWN_THREAT_TYPE>"),
            "classification": threat.get("classification", "<UNKNOWN_CLASSIFICATION>"),
            "threatStatus": threat.get("threatStatus", "<UNKNOWN_THREAT_STATUS>"),
        }

        # Optionally include threatUrl for phishing detections
        if include_threat_url:
            threat_dict["threatUrl"] = threat.get("threatUrl")

        # Optionally include campaign-related fields
        if threat.get("campaignID"):
            threat_dict["campaignID"] = threat.get("campaignID", "<UNKNOWN_CAMPAIGN_ID>")
        if threat.get("threatID"):
            threat_dict["threatID"] = threat.get("threatID", "<UNKNOWN_THREAT_ID>")

        threats.append(threat_dict)

    return threats


def proofpoint_alert_context(event, include_threat_url=False):
    """
    Returns common alert context for Proofpoint email security events.

    Args:
        event: The Proofpoint event
        include_threat_url: Whether to include threatUrl in threat details

    Returns:
        Dictionary with standardized Proofpoint alert context
    """
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
        "threats": extract_threats(event, include_threat_url=include_threat_url),
    }
