from panther_otx_helpers import (
    get_otx_object,
    otx_alert_context,
    otx_severity_from_pulse,
    severity_greater_than,
)

MATCHED_INDICATORS = {}  # {indicator: {adversary, malware_families, indicator_type}}


def rule(event):
    global MATCHED_INDICATORS  # pylint: disable=global-statement
    MATCHED_INDICATORS = {}

    otx = get_otx_object(event)
    if not otx:
        return False

    for ip_addr in event.get("p_any_ip_addresses", []):
        indicator_type = otx.indicator_type(ip_addr)
        if not indicator_type:
            continue
        MATCHED_INDICATORS[ip_addr] = {
            "adversary": otx.adversary(ip_addr),
            "malware_families": otx.malware_families(ip_addr),
            "indicator_type": indicator_type,
        }

    return bool(MATCHED_INDICATORS)


def title(event):
    log_type = event.get("p_log_type", "Unknown")
    if len(MATCHED_INDICATORS) == 1:
        indicator, info = next(iter(MATCHED_INDICATORS.items()))
        ioc_type = info.get("indicator_type", "indicator")
        return f"OTX: Known threat {ioc_type} [{indicator}] detected in {log_type}"
    return f"OTX: {len(MATCHED_INDICATORS)} threat indicators detected in {log_type}"


def severity(event):  # pylint: disable=unused-argument
    highest = "INFO"
    for info in MATCHED_INDICATORS.values():
        sev = otx_severity_from_pulse(
            info.get("adversary", ""),
            info.get("malware_families", []),
        )
        if severity_greater_than(sev, highest):
            highest = sev
    return highest or "MEDIUM"


def alert_context(event):
    if not MATCHED_INDICATORS:
        return {}
    ctx = {}
    for indicator, info in MATCHED_INDICATORS.items():
        indicator_ctx = otx_alert_context(event, indicator)
        indicator_ctx["MatchedIndicatorType"] = info.get("indicator_type")
        ctx[indicator] = indicator_ctx
    return ctx
