# This policy ensures that users do not belong to groups that should be exclusive.
# A common example would be the Developer group and the Production admin group, as in tightly
# controlled environments developers should not be able to deploy to production directly and
# sysadmins should not have access to developmental source code.
#
# GROUP_CONFLICTS is formatted as a list of sets. Each inner set contains mutually exclusive groups.
GROUP_CONFLICTS = [
    {"PROD_ADMIN", "DEV"},
]


def policy(resource):
    group_names = {group["GroupName"] for group in resource["Groups"] or []}

    # If the user is in more than one group in a mutually exclusive set, return False
    for conflict_set in GROUP_CONFLICTS:
        if len(group_names.intersection(conflict_set)) > 1:
            return False

    return True
