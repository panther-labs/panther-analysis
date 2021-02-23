# pylint: disable=line-too-long
# SUNBURST IOCs: https://github.com/fireeye/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_NBIs.csv
# Last accessed: 12-5-2020
SUNBURST_FQDN_IOCS = {
    "databasegalore.com",
    "deftsecurity.com",
    "freescanonline.com",
    "highdatabase.com",
    "incomeupdate.com",
    "panhardware.com",
    "thedoccloud.com",
    "websitetheme.com",
    "zupertech.com",
    "6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud.com",
    "7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud.com",
    "gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com",
    "ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com",
    "k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud.com",
    "mhdosoksaccf9sni9icp.appsync-api.eu-west-1.avsvmcloud.com",
}

SUNBURST_IP_IOCS = {
    "5.252.177.21",
    "5.252.177.25",
    "13.59.205.66",
    "34.203.203.23",
    "51.89.125.18",
    "54.193.127.66",
    "54.215.192.52",
    "139.99.115.204",
    "167.114.213.199",
    "204.188.205.176",
}

SUNBURST_SHA256_IOCS = {
    "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134",
    "292327e5c94afa352cc5a02ca273df543f2020d0e76368ff96c84f4e90778712",
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7",
    "c15abaf51e78ca56c0376522d699c978217bf041a3bd3c71d09193efa5717c71",
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6",
    "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600",
}


def ioc_match(indicators: list, known_iocs: set) -> list:
    """Matches a set of indicators against known Indicators of Compromise

    :param indicators: List of potential indicators of compromise
    :param known_iocs: Set of known indicators of compromise
    :return: List of any indicator matches
    """
    # Check through the IP IOCs
    return [ioc for ioc in (indicators or []) if ioc in known_iocs]


def sanitize_domain(domain: str) -> str:
    """Makes a potential malicous domain not render as a domain in most systems

    :param domain: Original domain
    :return: Sanitized domain
    """
    return domain.replace(".", "[.]")
