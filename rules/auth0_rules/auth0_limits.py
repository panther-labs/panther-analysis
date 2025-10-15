from panther_core import PantherEvent

SUSPICIOUS_EVENT_TYPES = (
    "api_limit",
    "gd_otp_rate_limit_exceed",
    "gd_recovery_rate_limit_exceed",
    "limit_delegation",
    "limit_mu",
    "limit_sul",
    "limit_wc",
)

EVENT_TITLES = (
    "The maximum number of requests to the Authentication or Management APIs has been "
    "reached for {}",
    "Too many MFA failures occured for {}",
    "{} has entered a wrong recovery code too many times",
    "Rate limit exceeded to the delegation token endpoint by {}",
    "{} IP address is blocked because it attempted too many sign-ups or failed logins: {}",
    "{} is temporarily blocked from logging in because they reached the maximum logins from {}",
    "{} IP address is blocked because it reached the maximum failed login attempts into a "
    "single account: {}",
)


def rule(event: PantherEvent) -> bool:
    return event.deep_get("data", "type") in SUSPICIOUS_EVENT_TYPES


def title(event: PantherEvent) -> str:
    limit_mu_index = SUSPICIOUS_EVENT_TYPES.index("limit_mu")
    limit_sul_index = SUSPICIOUS_EVENT_TYPES.index("limit_sul")
    limit_wc_index = SUSPICIOUS_EVENT_TYPES.index("limit_wc")

    event_type = event.deep_get("data", "type")
    event_index = SUSPICIOUS_EVENT_TYPES.index(event_type)
    event_title = EVENT_TITLES[event_index]

    # limit_mu or limit_wc
    if event_index in {limit_mu_index, limit_wc_index}:
        ip_address = event.deep_get("data", "ip", default="NO_IP_FOUND")
        username = event.deep_get("data", "user_name", default="NO_USER_FOUND")
        return event_title.format(ip_address, username)

    # limit_sul
    if event_index == limit_sul_index:
        ip_address = event.deep_get("data", "ip", default="NO_IP_FOUND")
        username = event.deep_get("data", "user_name", default="NO_USER_FOUND")
        return event_title.format(username, ip_address)

    # other cases have only "user_name" field in their titles
    username = event.deep_get("data", "user_name", default="NO_USER_FOUND")
    return event_title.format(username)
