def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="")
            in ["sso-directory.amazonaws.com", "sso.amazonaws.com"],
            event.deep_get("eventName", default="")
            in [
                "AssociateDirectory",
                "DisableExternalIdPConfigurationForDirectory",
                "DisassociateDirectory",
                "EnableExternalIdPConfigurationForDirectory",
            ],
        ]
    ):
        return True
    return False
