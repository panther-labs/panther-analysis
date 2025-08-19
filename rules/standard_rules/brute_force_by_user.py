from json import loads

import panther_event_type_helpers as event_type
from panther_base_helpers import add_parse_delay
from panther_ipinfo_helpers import PantherIPInfoException, geoinfo_from_ip


def rule(event):
    # filter events on unified data model field
    return event.udm("event_type") == event_type.FAILED_LOGIN


def title(event):
    # use unified data model field in title
    log_type = event.get("p_log_type")
    title_str = (
        f"{log_type}: User [{event.udm('actor_user')}] has exceeded the failed logins threshold"
    )
    if log_type == "AWS.CloudTrail":
        title_str += f" in [{event.get('recipientAccountId')}]"
    return title_str


def alert_context(event):
    try:
        geoinfo = geoinfo_from_ip(event=event, match_field=event.udm_path("source_ip"))
    except PantherIPInfoException:
        geoinfo = {}
    if isinstance(geoinfo, str):
        geoinfo = loads(geoinfo)
    context = {}
    context["geolocation"] = (
        f"{geoinfo.get('city')}, {geoinfo.get('region')} in " f"{geoinfo.get('country')}"
    )
    context["ip"] = geoinfo.get("ip")
    context["reverse_lookup"] = geoinfo.get("hostname", "No reverse lookup hostname")
    context["ip_org"] = geoinfo.get("org", "No organization listed")
    try:
        context = add_parse_delay(event, context)
    except TypeError:
        pass
    except AttributeError:
        pass
    return context
