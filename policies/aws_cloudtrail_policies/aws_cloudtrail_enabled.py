def policy(resource):
    if not (resource.get("Trails") or resource.get("TrailARN")):
        return False

    if not (resource.get("GlobalEventSelectors") or resource.get("GlobalAdvancedEventSelectors")):
        return False

    for selector in resource.get("GlobalEventSelectors", [{}]):
        if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
            return True

    for advanced_selector in resource.get("GlobalAdvancedEventSelectors", [{}]):
        management_present = False
        readOnly_excluded = True
        for field_selector in advanced_selector.get("FieldSelectors", [{}]):
            if field_selector.get("Field") == "eventCategory":
                eventCategories = field_selector.get("Equals", [])
                if "Management" in eventCategories:
                    management_present = True
            if field_selector.get("Field") == "readOnly":
                readOnly_excluded = False
        if readOnly_excluded and management_present:
            return True
    return False
