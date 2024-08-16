import panther_event_type_helpers as event_type
from panther_base_helpers import expand_country_code

# Configuration Required:
#   Configure the below list of rogue states according to your needs/experience
#   Refer to the link below to find the alpha-2 code corresponding to your country
#   https://www.iban.com/country-codes
ROGUE_STATES = {
    "CN",
    "IR",
    "RU"
}

def rule(event):
    # Only evaluate successful logins
    if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
        return False
    
    # Get contry of request origin and compare to identified rogue state list
    return bool(is_rogue_state(get_country(event)))


def title(event):
    log_type = event.get("p_log_type")
    country = get_country(event)
    account_name = get_account_name(event)
    return f"{log_type}: Sign-In for account {account_name} from Rogue State '{expand_country_code(country)}'"


def alert_context(event):
    return {
        "source_ip": event.udm("source_ip"),
        "country": get_country(event),
        "account_name": get_account_name(event)
    }


def get_country(event) -> str:
    """Returns the country code from an event's IPinfo data."""
    location_data = event.deep_get("p_enrichment", "ipinfo_location", event.udm_path("source_ip"))
    if not location_data:
        return "" # Ignore event if we have no enrichment to analyze
    return location_data.get("country").upper()


def get_account_name(event) -> str:
    """ Returns the account name. """
    if account_name := event.deep_get("p_udm", "user", "email"):
        return account_name
    elif account_name := event.deep_get("p_udm", "user", "name"):
        return account_name
    elif account_name := event.udm("actor_user"):
        return account_name
    return "UNKNWON ACCOUNT"


def is_rogue_state(country_code: str) -> bool:
    """Returns whether the country code provided belongs to an identified rogue state."""
    # This function makes it easy for us to use unit test mocks to ensure altering the ROGUE_STATES
    #   dict doesn't break our test suite.
    return country_code in ROGUE_STATES