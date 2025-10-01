from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    return event.deep_get("data", "type") == "pwd_leak"


def title(event: PantherEvent) -> str:
    ip_address = event.deep_get("data", "ip", default="NO_IP_FOUND")
    user_name = event.deep_get("data", "user_name", default="NO_USERNAME")
    event_title = (
        "Someone behind the IP address {} attempted to login with a leaked password "
        "with username {}"
    )

    return event_title.format(ip_address, user_name)
