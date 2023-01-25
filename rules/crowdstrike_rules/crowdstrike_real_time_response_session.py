from panther_base_helpers import get_crowdstrike_field

MATCHES = []


def rule(event):
    return (
        get_crowdstrike_field(event, "ExternalApiType", default="<unknown-ExternalApiType>")
        == "Event_RemoteResponseSessionStartEvent"
    )


def title(event):
    user_name = get_crowdstrike_field(event, "UserName",
                                      default="<unknown-UserName>")
    hostname_field = get_crowdstrike_field(event, "HostnameField",
                                           default="<unknown-HostNameField>")
    return f"{user_name} started a Crowdstrike Real-Time Response (RTR) shell on {hostname_field}"


def alert_context(event):
    # pylint: disable=line-too-long
    return {
        "Start Time": get_crowdstrike_field(event, "StartTimestamp",
                                            default="<unknown-StartTimestamp>"),
        "SessionId": get_crowdstrike_field(event, "SessionId",
                                           default="<unknown-SessionId>"),
        "Actor": get_crowdstrike_field(event, "UserName",
                                       default="<unknown-UserName>"),
        "Target Host": get_crowdstrike_field(event, "HostnameField",
                                             default="<unknown-HostnameField>"),
    }
