from panther_base_helpers import deep_get


def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Crowdstrike FDR end with a trailing period, such as google.com.
    domain = deep_get(event, "event", "DomainName", default=None)
    if domain:
        domain = domain.rstrip(".").lower()
    return domain


def get_process_name(event):
    platform = event.get("event_platform")
    # Extract process name from path
    # Win = \Device\HarddiskVolume2\Windows\System32\winlogon.exe
    # Lin = /usr/bin/run-parts
    # Mac = /usr/libexec/xpcproxy
    image_fn = deep_get(event, "event", "ImageFileName")
    if not image_fn:
        return None  # Explicitly return None if the key DNE
    if platform == "Win":
        return image_fn.split("\\")[-1]
    return image_fn.split("/")[-1]
