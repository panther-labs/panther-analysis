from panther_azuresignin_helpers import azure_signin_alert_context

MICROSOFT_ASNS = {
    "8075",  # Microsoft Corporation
    "8068",  # Microsoft Corporation
    "8069",  # Microsoft Corporation
    "8070",  # Microsoft Corporation
    "12076",  # Microsoft Azure
}


def rule(event):
    error_code = event.deep_get("properties", "status", "errorCode", default=None)
    asn = event.deep_get("properties", "autonomousSystemNumber", default="")
    user_principal_name = event.deep_get("properties", "userPrincipalName", default="")

    # Exclude Microsoft ASN
    return all([error_code == 50053, asn not in MICROSOFT_ASNS, user_principal_name])


def title(event):
    user_principal_name = event.deep_get(
        "properties", "userPrincipalName", default="<UNKNOWN_USER>"
    )

    return f"Excessive Account Lockouts Detected for [{user_principal_name}]"


def alert_context(event):
    context = azure_signin_alert_context(event)

    # Add lockout-specific context
    context["error_code"] = event.deep_get("properties", "status", "errorCode", default=None)
    context["failure_reason"] = event.deep_get(
        "properties", "status", "failureReason", default="<NO_REASON>"
    )
    context["user_agent"] = event.deep_get("properties", "userAgent", default="<NO_USER_AGENT>")
    context["app_display_name"] = event.deep_get("properties", "appDisplayName", default="<NO_APP>")
    context["location_city"] = event.deep_get("properties", "location", "city", default="<NO_CITY>")
    context["location_country"] = event.deep_get(
        "properties", "location", "countryOrRegion", default="<NO_COUNTRY>"
    )
    context["asn"] = event.deep_get("properties", "autonomousSystemNumber", default="<NO_ASN>")

    return context
