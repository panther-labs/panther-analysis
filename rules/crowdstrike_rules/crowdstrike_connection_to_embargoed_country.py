from panther_base_helpers import crowdstrike_network_detection_alert_context, deep_get

# U.S. Gov Sanctioned Destinations
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
    # enrichment_object returns a list.
    # Iterate over list and check if the "country" value matches the country codes.
    if enrichment_obj:
        if [i for i in enrichment_obj if i["country"] in EMBARGO_COUNTRY_CODES]:
            return True
    return False


def title(event):
    enrichment_obj = get_enrichment_obj(event)
    # return country code value if a match is found to craft the title
    country_code = [
        i.get("country") for i in enrichment_obj if i["country"] in EMBARGO_COUNTRY_CODES
    ][0]
    return f"Connection made to embargoed country: {country_code}."


def alert_context(event):
    if event.get("p_log_type") == "Crowdstrike.FDREvent":
        return crowdstrike_network_detection_alert_context(event) | {
            "p_any_ip_addresses": event.get("p_any_ip_addresses")
        }

    return {"p_any_ip_addresses": event.get("p_any_ip_addresses")}
