# SUNBURST IOCs https://github.com/fireeye/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_NBIs.csv
# Last accessed: 12-5-2020
SUNBURST_FQDN_IOCS = [
    'databasegalore.com',
    'deftsecurity.com',
    'freescanonline.com',
    'highdatabase.com',
    'incomeupdate.com',
    'panhardware.com',
    'thedoccloud.com',
    'websitetheme.com',
    'zupertech.com',
    '6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud.com',
    '7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud.com',
    'gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com',
    'ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com',
    'k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud.com',
    'mhdosoksaccf9sni9icp.appsync-api.eu-west-1.avsvmcloud.com',
]
SUNBURST_IP_IOCS = [
    '5.252.177.21', '5.252.177.25', '13.59.205.66', '34.203.203.23',
    '51.89.125.18', '54.193.127.66', '54.215.192.52', '139.99.115.204',
    '167.114.213.199', '204.188.205.176'
]
SUNBURST_SHA256_IOCS = [
    '019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134',
    '292327e5c94afa352cc5a02ca273df543f2020d0e76368ff96c84f4e90778712',
    '32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77',
    '53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7',
    'c15abaf51e78ca56c0376522d699c978217bf041a3bd3c71d09193efa5717c71',
    'ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6',
    'd0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600'
]


def intersection(first: list, second: list) -> list:
    return list(set(first) & set(second))


def sunburst_fqdn_ioc_match(event: dict) -> bool:
    """Matches a Fully Qualified Domain Name against known Sunburst Indicators of Compromise

    :param event: Dictionary containing the event details
    :return: Boolean indicating whether or not it was a match
    """
    # Check through the IP IOCs
    if event.get("p_any_domain_names") is not None:
        for each_fqdn in event.get("p_any_domain_names"):
            if each_fqdn in SUNBURST_FQDN_IOCS:
                return True
    return False


def sunburst_ip_ioc_match(event: dict) -> bool:
    """Matches an IP address against known Sunburst Indicators of Compromise

    :param event: Dictionary containing the event details
    :return: Boolean indicating whether or not it was a match
    """
    # Check against src/dst addr
    if event.get("srcaddr") in SUNBURST_IP_IOCS or event.get(
            "dstaddr") in SUNBURST_IP_IOCS:
        return True
    # Check through the IP IOCs
    if event.get("p_any_ip_addresses") is not None:
        for each_ip in event.get("p_any_ip_addresses"):
            if each_ip in SUNBURST_IP_IOCS:
                return True
    return False


def sunburst_sha256_ioc_match(event: dict) -> bool:
    """Matches a SHA-256 against known Sunburst Indicators of Compromise

    :param event: Dictionary containing the event details
    :return: Boolean indicating whether or not it was a match
    """
    # Check through the SHA-256 IOCs
    if event.get("p_any_sha256_hashes") is not None:
        for each_checksum in event.get("p_any_sha256_hashes"):
            if each_checksum in SUNBURST_SHA256_IOCS:
                return True
    return False
