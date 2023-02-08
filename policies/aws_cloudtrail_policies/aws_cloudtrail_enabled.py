def policy(resource):
    # pylint: disable=R1260
    if not resource.get("Trails"):
        return False

    if not any([
        resource.get("GlobalEventSelectors"),
        resource.get("GlobalAdvancedEventSelectors")
        ]):
        return False

    for selector in resource.get("GlobalEventSelectors", [{}]):
        if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
            return True

    for advanced_selector in resource.get("GlobalAdvancedEventSelectors", [{}]):
        management_present = False
        readonly_excluded = True
        for field_selector in advanced_selector.get("FieldSelectors", [{}]):
            if field_selector.get("Field") == "eventCategory":
                event_categories = field_selector.get("Equals", [])
                if "Management" in event_categories:
                    management_present = True
            if field_selector.get("Field") == "readOnly":
                readonly_excluded = False
        if readonly_excluded and management_present:
            return True
    return False
