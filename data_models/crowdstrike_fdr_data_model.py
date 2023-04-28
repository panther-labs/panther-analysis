from panther_base_helpers import deep_get

def get_dns_query(event):
    # Strip trailing period. Domain Names from Crowdstrike FDR end with a trailing period, such as google.com. 
    domain = deep_get(event, 'event', 'DomainName', default=None)
    if domain:
        domain = ".".join(domain.rstrip(".").split(".")[-2:]).lower()
    return domain