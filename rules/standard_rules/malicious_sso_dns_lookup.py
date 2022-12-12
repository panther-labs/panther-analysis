"""
We highly recommend running this logic over 30 days of historical data using data replay
before enabling this in your Panther instance. If ALLOWED_DOMAINS is not fully populated with
domains you own, that contain your company name, false positive alerts will be generated.

Recommended steps to enable:
    1. Change COMPANY_NAME to match your organization
    2. Update the occurrences of "company_name_here" in malicious_sso_dns_lookup.yml
    3. Add known domains containing COMPANY_NAME to ALLOWED_DOMAINS
    4. Run local tests
    5. Run a Data Replay test to identify unknown domains that should be in ALLOWED_DOMAINS
"""


# *** Change this to match your company name ***
COMPANY_NAME = "company_name_here"

# Ref: https://blog.group-ib.com/0ktapus
FAKE_KEYWORDS = [
    "sso",
    "okta",
    "corp",
    "vpn",
    "citrix",
    "help",
    "edge",
]

# Add known good domains that contain your company name
ALLOWED_DOMAINS = [
    ".amazonaws.com",
    ".okta.com",
    ".oktapreview.com",
    #   "COMPANY.com",
]


def rule(event):
    # check domain for company name AND a fake keyword
    for domain in event.get("p_any_domain_names", []):
        domain_was_allowed = [x for x in ALLOWED_DOMAINS if domain.lower().endswith(x)]
        if domain_was_allowed:
            continue
        if COMPANY_NAME in domain.lower():
            fake_matches = [x for x in FAKE_KEYWORDS if x in domain.lower()]
            if fake_matches:
                return True

    # The domain did not have a fake keyword and the company name
    return False


def title(event):
    return f"Potential Malicious SSO Domain - {event.get('p_any_domain_names','')[0]}"
