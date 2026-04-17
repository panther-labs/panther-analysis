def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Cisco Umbrella end with a trailing period, such as google.com.
    domain = event.get("domain")
    if domain:
        domain = domain.rstrip(".")
    return domain
