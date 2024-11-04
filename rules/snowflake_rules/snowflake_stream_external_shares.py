# CONFIGURATION REQUIRED
#   Be sure to add code to exclude any transfers from acounts designed to host data shares. Either
#   add those account names to the set below, or add a rule filter to exclude events with those
#   account names.
DATA_SHARE_HOSTING_ACCOUNTS = {
    # Add account names here
}


def rule(event):
    return all(
        [
            event.get("ACCOUNT_NAME") not in get_data_share_hosting_accounts(),
            event.get("SOURCE_CLOUD"),
            event.get("TARGET_CLOUD"),
            event.get("BYTES_TRANSFERRED", 0) > 0,
        ]
    )


def title(event):
    return (
        f"{event.get('ORGANIZATION_NAME', '<UNKNOWN ORGANIZATION>')}: "
        "A data export has been initiated from source cloud "
        f"{event.get('SOURCE_CLOUD', '<UNKNOWN SOURCE CLOUD>')} "
        f"in source region {event.get('SOURCE_REGION', '<UNKNOWN SOURCE REGION>')} "
        f"to target cloud {event.get('TARGET_CLOUD', '<UNKNOWN TARGET CLOUD>')} "
        f"in target region {event.get('TARGET_REGION', '<UNKNOWN TARGET REGION>')} "
        f"with transfer type {event.get('TRANSFER_TYPE', '<UNKNOWN TRANSFER TYPE>')} "
        f"for {event.get('BYTES_TRANSFERRED', '<UNKNOWN VOLUME>')} bytes"
    )


def get_data_share_hosting_accounts():
    """Getter function. Used so we can mock during unit tests."""
    return DATA_SHARE_HOSTING_ACCOUNTS
