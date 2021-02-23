def policy(resource):
    if not resource["Trails"]:
        return False

    if not resource["GlobalEventSelectors"]:
        return False

    for selector in resource["GlobalEventSelectors"]:
        if selector["IncludeManagementEvents"] and selector["ReadWriteType"] == "All":
            return True

    return False
