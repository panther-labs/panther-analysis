from panther_greynoise_helpers import (
    get_greynoise_v3_business_service_object,
    get_greynoise_v3_object,
    greynoise_v3_alert_context,
    greynoise_v3_severity,
)

CLASSIFICATIONS_TO_ALERT = {"malicious", "unknown"}

MATCHED_IPS = {}  # {ip: classification}
SCANNER = None


def rule(event):
    global MATCHED_IPS, SCANNER  # pylint: disable=global-statement
    MATCHED_IPS = {}
    SCANNER = None

    scanner = get_greynoise_v3_object(event)
    if not scanner:
        return False

    bsi = get_greynoise_v3_business_service_object(event)

    for ip_addr in event.get("p_any_ip_addresses", []):
        if bsi and bsi.found(ip_addr):
            continue

        classification = scanner.classification(ip_addr)
        if not classification or classification == "benign":
            continue

        if classification in CLASSIFICATIONS_TO_ALERT:
            MATCHED_IPS[ip_addr] = classification

    if MATCHED_IPS:
        SCANNER = scanner
        return True
    return False


def title(event):
    log_type = event.get("p_log_type", "Unknown")
    if len(MATCHED_IPS) == 1:
        ip_addr, classification = next(iter(MATCHED_IPS.items()))
        return f"GreyNoise: {classification.title()} IP [{ip_addr}] detected in {log_type}"
    return f"GreyNoise: {len(MATCHED_IPS)} suspicious IPs detected in {log_type}"


def severity(event):
    # Use the highest-severity matched IP
    for ip_addr in MATCHED_IPS:
        return greynoise_v3_severity(event, ip_addr)
    return "MEDIUM"


def alert_context(event):
    if not MATCHED_IPS:
        return {}
    ctx = {}
    for ip_addr, classification in MATCHED_IPS.items():
        ip_ctx = greynoise_v3_alert_context(event, ip_addr)
        ip_ctx["MatchedClassification"] = classification
        ctx[ip_addr] = ip_ctx
    return ctx
