from panther_aws_helpers import aws_rule_context, lookup_aws_account_name


def rule(event):
    """
    Detects AWS console login attempts from IP addresses located outside California.
    Uses IPInfo location enrichment data to determine geographic location.
    """
    # Only look at Console Login events
    if event.get("eventName") != "ConsoleLogin":
        return False
    
    # Only alert on successful logins
    if event.deep_get("responseElements", "ConsoleLogin") != "Success":
        return False
    
    # Check if we have ipinfo location enrichment data for the source IP
    location_data = event.deep_get("p_enrichment", "ipinfo_location", "sourceIPAddress")
    if not location_data:
        return False
    
    # Get country and region information from IPInfo enrichment
    country = location_data.get("country")
    region = location_data.get("region")
    
    # Alert if login is from outside California
    # This includes both non-US locations and other US states
    if country and region:
        if country.upper() != "US" or region != "California":
            return True
    
    return False


def title(event):
    """
    Generate a descriptive alert title including location information.
    """
    location_data = event.deep_get("p_enrichment", "ipinfo_location", "sourceIPAddress", default={})
    city = location_data.get("city", "Unknown")
    region = location_data.get("region", "Unknown")
    country = location_data.get("country", "Unknown")
    user_name = _get_user_name(event)
    account_name = lookup_aws_account_name(event.get("recipientAccountId"))
    
    return (
        f"AWS Console login from outside California detected: "
        f"User '{user_name}' logged in from {city}, {region} ({country}) "
        f"in account [{account_name}]"
    )


def alert_context(event):
    """
    Provide additional context for the alert including user details and location information.
    """
    location_data = event.deep_get("p_enrichment", "ipinfo_location", "sourceIPAddress", default={})

    context = {
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userIdentityType": event.deep_get("userIdentity", "type"),
        "userIdentityArn": event.deep_get("userIdentity", "arn"),
        "userName": _get_user_name(event),
        "eventTime": event.get("eventTime"),
        "userAgent": event.get("userAgent"),
        "mfaUsed": event.deep_get("additionalEventData", "MFAUsed"),
        "location": {
            "city": location_data.get("city"),
            "region": location_data.get("region"),
            "country": location_data.get("country"),
            "country_name": _get_country_name(location_data.get("country")),
            "timezone": location_data.get("timezone"),
            "latitude": location_data.get("lat"),
            "longitude": location_data.get("lng"),
            "postal_code": location_data.get("postal_code")
        }
    }

    # Add session context for AssumedRole logins
    if event.deep_get("userIdentity", "type") == "AssumedRole":
        session_context = event.deep_get("userIdentity", "sessionContext") or {}
        context["sessionContext"] = {
            "mfaAuthenticated": session_context.get("attributes", {}).get("mfaAuthenticated"),
            "creationDate": session_context.get("attributes", {}).get("creationDate"),
            "sessionIssuer": session_context.get("sessionIssuer")
        }
    
    # Add AWS-specific context from helper
    context.update(aws_rule_context(event))
    
    return context


def _get_user_name(event):
    """
    Extract username from event, handling different user identity types.
    For AssumedRole, extracts the username from the principalId or ARN.
    """
    user_identity_type = event.deep_get("userIdentity", "type")

    # Handle AssumedRole case - extract username from principalId or ARN
    if user_identity_type == "AssumedRole":
        # Try principalId first (format: AROA...:username)
        principal_id = event.deep_get("userIdentity", "principalId")
        if principal_id and ":" in principal_id:
            return principal_id.split(":")[-1]

        # Fallback to ARN parsing (format: arn:aws:sts::account:assumed-role/RoleName/username)
        arn = event.deep_get("userIdentity", "arn")
        if arn and "/" in arn:
            return arn.split("/")[-1]

    # Handle standard cases (IAMUser, Root, etc.)
    user_name = event.deep_get("userIdentity", "userName")
    if user_name:
        return user_name

    # Fallback to user identity type
    return user_identity_type or "Unknown"


def _get_country_name(country_code):
    """
    Convert ISO 3166-1 alpha-2 country codes to full country names for common countries.
    """
    country_names = {
        "CA": "Canada",
        "GB": "United Kingdom",
        "FR": "France", 
        "DE": "Germany",
        "JP": "Japan",
        "AU": "Australia",
        "IN": "India",
        "CN": "China",
        "BR": "Brazil",
        "MX": "Mexico",
        "IT": "Italy",
        "ES": "Spain",
        "RU": "Russia",
        "KR": "South Korea",
        "NL": "Netherlands",
        "SG": "Singapore",
        "SE": "Sweden",
        "NO": "Norway",
        "DK": "Denmark",
        "FI": "Finland",
        "IE": "Ireland",
        "BE": "Belgium",
        "CH": "Switzerland",
        "AT": "Austria",
        "PT": "Portugal",
        "IL": "Israel",
        "ZA": "South Africa",
        "AR": "Argentina",
        "CL": "Chile",
        "CO": "Colombia",
        "PE": "Peru",
        "VE": "Venezuela",
        "TH": "Thailand",
        "MY": "Malaysia",
        "ID": "Indonesia",
        "PH": "Philippines",
        "VN": "Vietnam",
        "TW": "Taiwan",
        "HK": "Hong Kong",
        "NZ": "New Zealand",
        "EG": "Egypt",
        "NG": "Nigeria",
        "KE": "Kenya",
        "GH": "Ghana",
        "MA": "Morocco",
        "TN": "Tunisia",
        "PL": "Poland",
        "CZ": "Czech Republic",
        "HU": "Hungary",
        "RO": "Romania",
        "GR": "Greece",
        "BG": "Bulgaria",
        "HR": "Croatia",
        "SK": "Slovakia",
        "SI": "Slovenia",
        "LT": "Lithuania",
        "LV": "Latvia",
        "EE": "Estonia",
        "TR": "Turkey",
        "SA": "Saudi Arabia",
        "AE": "United Arab Emirates",
        "QA": "Qatar",
        "KW": "Kuwait",
        "OM": "Oman",
        "BH": "Bahrain",
        "JO": "Jordan",
        "LB": "Lebanon",
        "IQ": "Iraq",
        "IR": "Iran",
        "PK": "Pakistan",
        "BD": "Bangladesh",
        "LK": "Sri Lanka",
        "NP": "Nepal",
        "MM": "Myanmar",
        "KH": "Cambodia",
        "LA": "Laos",
        "UZ": "Uzbekistan",
        "KZ": "Kazakhstan",
        "KG": "Kyrgyzstan",
        "TJ": "Tajikistan",
        "TM": "Turkmenistan",
        "AF": "Afghanistan",
        "MN": "Mongolia"
    }
    
    return country_names.get(country_code, country_code)
