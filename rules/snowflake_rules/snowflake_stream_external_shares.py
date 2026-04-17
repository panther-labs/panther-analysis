def rule(event):
    return all(
        [
            event.get("SOURCE_CLOUD"),
            event.get("TARGET_CLOUD"),
            event.get("BYTES_TRANSFERRED", 0) > 0,
        ]
    )


def title(event):
    return (
        f"A data export has been initiated from source cloud "
        f"{event.get('SOURCE_CLOUD', '<UNKNOWN SOURCE CLOUD>')} "
        f"in source region {event.get('SOURCE_REGION', '<UNKNOWN SOURCE REGION>')} "
        f"to target cloud {event.get('TARGET_CLOUD', '<UNKNOWN TARGET CLOUD>')} "
        f"in target region {event.get('TARGET_REGION', '<UNKNOWN TARGET REGION>')} "
        f"with transfer type {event.get('TRANSFER_TYPE', '<UNKNOWN TRANSFER TYPE>')} "
        f"for {event.get('BYTES_TRANSFERRED', '<UNKNOWN VOLUME>')} bytes"
    )
