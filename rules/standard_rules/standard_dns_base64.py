import re

from panther_base_helpers import defang_ioc


def rule(event):
    # Return True to match the log event and trigger an alert.

    # To reduce FPs, don't match against leading subdomains that are only 4 characters in length.
    # Four base64 characters can only represent 1-3 characters in length.
    subdomain_len = len(event.udm("dns_query").split(".")[0])

    if subdomain_len < 5:
        return False

    # Search for valid Base64 strings
    base64_pattern = re.compile(
        r"^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\."
    )

    return bool(base64_pattern.search(event.udm("dns_query")))


def title(event):
    defang_query = defang_ioc(event.udm("dns_query"))
    return f'Base64 encoded query detected from [{event.udm("source_ip")}], [{defang_query}]'
