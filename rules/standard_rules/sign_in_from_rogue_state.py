import panther_event_type_helpers as event_type
import pycountry

# Configuration Required:
#   Configure the below list of rogue states according to your needs/experience
#   Refer to the link below to find the alpha-2 code corresponding to your country
#   https://www.iban.com/country-codes
ROGUE_STATES = {"CN", "IR", "RU"}


def rule(event):
    # Only evaluate successful logins
    if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
        return False

    # Ignore events with no IP data
    if not event.udm("source_ip"):
        return False

    # Get contry of request origin and compare to identified rogue state list
    country = get_country(event)
    if country is None:
        # We weren't able to find a matching country, therefore we don't have enough information
        #   to alert on
        return False
    #   Wrapping in 'bool' so that we can use mocking for 'is_rogue_state'
    return bool(is_rogue_state(country.alpha_2))


def title(event):
    log_type = event.get("p_log_type")
    country = get_country(event)
    account_name = get_account_name(event)
    return f"{log_type}: Sign-In for account {account_name} from Rogue State '{country.name}'"


def alert_context(event):
    return {
        "source_ip": event.udm("source_ip"),
        "country": get_country(event).name,
        "account_name": get_account_name(event),
    }


def get_country(event) -> str:
    """Returns the country code from an event's IPinfo data."""
    location_data = event.deep_get("p_enrichment", "ipinfo_location", event.udm_path("source_ip"))
    if not location_data:
        return None  # Ignore event if we have no enrichment to analyze
    return pycountry.countries.get(alpha_2=location_data.get("country").upper())


def get_account_name(event) -> str:
    """Returns the account name."""
    if account_name := event.udm("actor_user"):
        return account_name
    return "UNKNOWN ACCOUNT"


def is_rogue_state(country_code: str) -> bool:
    """Returns whether the country code provided belongs to an identified rogue state."""
    # This function makes it easy for us to use unit test mocks to ensure altering the ROGUE_STATES
    #   dict doesn't break our test suite.
    return country_code in ROGUE_STATES
