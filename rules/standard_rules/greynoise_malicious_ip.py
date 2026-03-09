from panther_greynoise_helpers import (
    get_greynoise_v3_business_service_object,
    get_greynoise_v3_object,
    greynoise_v3_alert_context,
)

CLASSIFICATIONS_TO_ALERT = {"malicious", "unknown"}

MATCHED_IP = None
SCANNER = None


def rule(event):
    global MATCHED_IP, SCANNER  # pylint: disable=global-statement
    MATCHED_IP = None
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
            MATCHED_IP = ip_addr
            SCANNER = scanner
            return True

    return False


def title(event):
    log_type = event.get("p_log_type", "Unknown")
    classification = SCANNER.classification(MATCHED_IP) if SCANNER else "malicious"
    return f"GreyNoise: {classification.title()} IP [{MATCHED_IP}] detected in {log_type}"


def severity(event):  # pylint: disable=unused-argument
    if SCANNER and SCANNER.classification(MATCHED_IP) == "malicious":
        return "HIGH"
    return "INFO"


def alert_context(event):
    if not MATCHED_IP:
        return {}
    return greynoise_v3_alert_context(event, MATCHED_IP)
