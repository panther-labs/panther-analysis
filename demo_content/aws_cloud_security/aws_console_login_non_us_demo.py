from panther_aws_helpers import aws_rule_context, lookup_aws_account_name


def rule(event):
    """
    Detects AWS console login attempts from IP addresses located outside the United States.
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
    
    # Get country information from IPInfo enrichment
    country = location_data.get("country")
    
    # Alert if login is from outside the US
    if country and country.upper() != "US":
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
    user_name = event.deep_get("userIdentity", "userName") or event.deep_get("userIdentity", "type", default="Unknown")
    account_name = lookup_aws_account_name(event.get("recipientAccountId"))
    
    return (
        f"AWS Console login from outside US detected: "
        f"User '{user_name}' logged in from {city}, {region} ({country}) "
        f"in account [{account_name}]"
    )


def dedup(event):
    """
    Deduplication key to group similar events together.
    Groups by user identity, account, and source IP to avoid alert spam.
    """
    return "-".join([
        event.deep_get("userIdentity", "arn", default="unknown"),
        event.get("recipientAccountId", "unknown"),
        event.get("sourceIPAddress", "unknown")
    ])


def alert_context(event):
    """
    Provide additional context for the alert including user details and location information.
    """
    location_data = event.deep_get("p_enrichment", "ipinfo_location", "sourceIPAddress", default={})
    
    context = {
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userIdentityType": event.deep_get("userIdentity", "type"),
        "userIdentityArn": event.deep_get("userIdentity", "arn"),
        "userName": event.deep_get("userIdentity", "userName"),
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
    
    # Add AWS-specific context from helper
    context.update(aws_rule_context(event))
    
    return context


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
