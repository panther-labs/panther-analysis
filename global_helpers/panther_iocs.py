# pylint: disable=line-too-long
# SUNBURST IOCs:
# https://github.com/fireeye/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_NBIs.csv
# Last accessed: 2021-11-17
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

SUNBURST_IP_IOCS = {"0.0.0.1"}

# https://github.com/mandiant/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_Hashes.csv
# Last accessed: 2021-11-17
SUNBURST_SHA256_IOCS = {
    "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134",
    "292327e5c94afa352cc5a02ca273df543f2020d0e76368ff96c84f4e90778712",
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7",
    "abe22cf0d78836c3ea072daeaf4c5eeaf9c29b6feb597741651979fc8fbd2417",
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6",
    "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600",
}

# LOG4J IOCs:
# IPs Pulled from the following sources, deduped and compiled here.
# https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217
# https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv
# https://raw.githubusercontent.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228/main/Threatview.io-log4j2-IOC-list
# Created 12-13-21

LOG4J_IP_IOCS = {
    # The rule using this set has been deprecated and disabled by default
    "0.0.0.1"
}

# Example sources:
# - https://www.fastly.com/blog/new-data-and-insights-into-log4shell-attacks-cve-2021-44228
# - https://news.sophos.com/en-us/2021/12/12/log4shell-hell-anatomy-of-an-exploit-outbreak/
LOG4J_EXPLOIT_IOCS = {
    "jndi:ldap:/",
    "jndi:rmi:/",
    "jndi:ldaps:/",
    "jndi:dns:/",
    "jndi:nis:/",
    "jndi:nds:/",
    "jndi:corba:/",
    "jndi:iiop:/",
    "jndi:${",
    "${jndi:",  # breadth
    "${lower:",  # example: ${jn${lower:d}i:l${lower:d}ap://example.${lower:c}om:1234/callback}
    "${upper:",  # example: ${jnd${upper:i}:ldap://example.com:1234/callback/}
    "${env:",  # example: ${jndi:ldap://example.com:1234/callback/${env:USER}
    "${sys:",  # example: ${jndi:ldap://example.com:1234/callback/${sys:java.version}
    "${java:",  # example: ${jndi:ldap://example.com:1234/callback/${java:os}
    "${date:",  # example: ${jndi:ldap://example.com:1234/callback/${date:MM-dd-yyyy}
    "${::-j",  # example: ${${::-j}${::-n}di:${::-l}d${::-a}p://example.com:1234/callback}
}

DIRTYPIPE_POC_HASHES = {
    "b52350c819dfd5c14359fca92dfcfcafd7c2a36b273546b1c94f6804cdd6b9d3",
    "0e40d0944ac44647ab51cf928914456a92606da6ebea5a47d44ee07783c78ec4",
    "3946337d1edc09f71394716b18b1bbc77fc8beb2cd23fa430b922c357172b93b",
    "092691d88c6dde0d8ad9a93f819657fec016e427e48a872faa6984af2202b529",
}

# IOC Helper functions:
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
