def policy(resource):
    # pylint: disable=R1260
    if not resource.get("Trails"):
        return False

    if not any(
        [resource.get("GlobalEventSelectors"), resource.get("GlobalAdvancedEventSelectors")]
    ):
        return False

    if resource.get("GlobalEventSelectors"):
        for selector in resource.get("GlobalEventSelectors", [{}]):
            if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
                return True

    if resource.get("GlobalAdvancedEventSelectors"):
        for advanced_selector in resource.get("GlobalAdvancedEventSelectors", [{}]):
            management_present = False
            readonly_present = False
            for field_selector in advanced_selector.get("FieldSelectors", [{}]):
                if field_selector.get("Field") == "eventCategory":
                    event_categories = field_selector.get("Equals", [])
                    if "Management" in event_categories:
                        management_present = True
                if field_selector.get("Field") == "readOnly":
                    readonly_present = True
            if all([management_present, not readonly_present]):
                return True
    return False
