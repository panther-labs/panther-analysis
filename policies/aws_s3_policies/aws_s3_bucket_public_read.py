from panther_base_helpers import deep_get

GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    "http://acs.amazonaws.com/groups/global/AllUsers",
}
PERMISSIONS = {"READ"}


def policy(resource):
    if "IsPublic" in resource and resource["IsPublic"]:
        return False

    for grant in resource["Grants"] or []:
        if deep_get(grant, "Grantee", "URI") in GRANTEES and grant.get("Permission") in PERMISSIONS:
            return False

    return True
