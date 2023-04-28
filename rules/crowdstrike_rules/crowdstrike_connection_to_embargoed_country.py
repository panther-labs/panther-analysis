from panther_base_helpers import crowdstrike_detection_alert_context, deep_get

EMBARGO_COUNTRY_CODES = {
    "CU",  # Cuba
    "IR",  # Iran
    "KP",  # DPRK
    "SY",  # Syria
}


def get_enrichment_obj(event):
    return deep_get(event, "p_enrichment", "ipinfo_location", "p_any_ip_addresses", default=None)


def rule(event):
    enrichment_obj = get_enrichment_obj(event)
    if enrichment_obj:
        if [i for i in enrichment_obj if i["country"] in EMBARGO_COUNTRY_CODES]:
            return True
    return False


def title(event):
    enrichment_obj = get_enrichment_obj(event)
    country_code = [
        i.get("country") for i in enrichment_obj if i["country"] in EMBARGO_COUNTRY_CODES
    ][0]
    return f"Connection made to embargoed country: {country_code}."


def alert_context(event):
    if event.get("p_log_type") == "Crowdstrike.FDREvent":
        return crowdstrike_detection_alert_context(event) | {
            "p_any_ip_addresses": event.get("p_any_ip_addresses")
        }

    return {"p_any_ip_addresses": event.get("p_any_ip_addresses")}
