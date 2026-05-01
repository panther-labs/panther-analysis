from panther_otx_helpers import (
    get_otx_object,
    otx_alert_context,
    otx_severity_from_pulse,
    severity_greater_than,
)

INDICATOR_FIELDS = (
    "p_any_ip_addresses",
    "p_any_domain_names",
    "p_any_md5_hashes",
    "p_any_sha1_hashes",
    "p_any_sha256_hashes",
    "p_any_emails",
)

MATCHED_INDICATORS = {}  # {indicator: {adversary, malware_families, indicator_type}}


def rule(event):
    global MATCHED_INDICATORS  # pylint: disable=global-statement
    MATCHED_INDICATORS = {}

    otx = get_otx_object(event)
    if not otx:
        return False

    for field in INDICATOR_FIELDS:
        for value in event.get(field, []) or []:
            if value in MATCHED_INDICATORS:
                continue
            indicator_type = otx.indicator_type(value)
            if not indicator_type:
                continue
            MATCHED_INDICATORS[value] = {
                "adversary": otx.adversary(value),
                "malware_families": otx.malware_families(value),
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
    highest = None
    for info in MATCHED_INDICATORS.values():
        sev = otx_severity_from_pulse(
            info.get("adversary", ""),
            info.get("malware_families", []),
        )
        if highest is None or severity_greater_than(sev, highest):
            highest = sev
    return highest or "DEFAULT"


def alert_context(event):
    if not MATCHED_INDICATORS:
        return {}
    ctx = {}
    for indicator, info in MATCHED_INDICATORS.items():
        indicator_ctx = otx_alert_context(event, indicator)
        indicator_ctx["MatchedIndicatorType"] = info.get("indicator_type")
        ctx[indicator] = indicator_ctx
    return ctx
