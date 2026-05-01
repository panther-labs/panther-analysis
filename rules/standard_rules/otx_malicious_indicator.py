from panther_otx_helpers import (
    get_otx_object,
    otx_alert_context,
    otx_severity,
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

MATCHED_INDICATORS = {}  # {indicator: indicator_type}


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
            MATCHED_INDICATORS[value] = indicator_type

    return bool(MATCHED_INDICATORS)


def title(event):
    log_type = event.get("p_log_type", "Unknown")
    if len(MATCHED_INDICATORS) == 1:
        indicator, ioc_type = next(iter(MATCHED_INDICATORS.items()))
        return f"OTX: Known threat {ioc_type} [{indicator}] detected in {log_type}"
    return f"OTX: {len(MATCHED_INDICATORS)} threat indicators detected in {log_type}"


def severity(event):
    highest = None
    for indicator in MATCHED_INDICATORS:
        sev = otx_severity(event, indicator)
        if highest is None or severity_greater_than(sev, highest):
            highest = sev
    return highest or "DEFAULT"


def alert_context(event):
    if not MATCHED_INDICATORS:
        return {}
    ctx = {}
    for indicator, indicator_type in MATCHED_INDICATORS.items():
        indicator_ctx = otx_alert_context(event, indicator)
        indicator_ctx["MatchedIndicatorType"] = indicator_type
        ctx[indicator] = indicator_ctx
    return ctx
