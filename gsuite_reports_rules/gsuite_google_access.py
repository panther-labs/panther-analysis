from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "access_transparency":
        return False

    return bool(details_lookup("GSUITE_RESOURCE", ["ACCESS"], event))
