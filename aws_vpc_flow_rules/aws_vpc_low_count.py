def rule(event):
    """
    Returns True for traffic seen smaller than 40 bytes and 2 or less packets
    This activity is a possible indicator of a Log4J RCE exploit attempt"
    Environments differ based upon usage, these parameters should be tuned to
    your use case
    """
    if event.get("action") == "ACCEPT":
        low_bytes = 40
        low_packets = 2
        return any((event.get("bytes") < low_bytes, event.get("packets") <= low_packets))
    return False


def title(event):
    return f"Unusually low byte or packet count from IP: {event.get('srcAddr')}"
