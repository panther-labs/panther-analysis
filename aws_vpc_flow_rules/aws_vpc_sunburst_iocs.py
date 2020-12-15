from ipaddress import ip_network

SUNBURST_FQDN_IOCS = [
    "6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud.com",
    "7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud.com",
    "gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com",
    "ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com",
    "k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud.com",
    "mhdosoksaccf9sni9icp.appsync-api.eu-west-1.avsvmcloud.com",
    "deftsecurity.com",
    "freescanonline.com",
    "thedoccloud.com",
    "websitetheme.com",
    "highdatabase.com",
    "incomeupdate.com",
    "databasegalore.com",
    "panhardware.com",
    "zupertech.com",
    "zupertech.com",
]

SUNBURST_IP_IOCS = [
    "13.59.205.66",
    "54.193.127.66",
    "54.215.192.52",
    "34.203.203.23",
    "139.99.115.204",
    "5.252.177.25",
    "5.252.177.21",
    "204.188.205.176",
    "51.89.125.18",
    "167.114.213.199",
]


def rule(event):
    # Check against src/dst addr
    if event.get("srcaddr") in SUNBURST_IP_IOCS or event.get(
            "dstaddr") in SUNBURST_IP_IOCS:
        return True

    # Check through the FQDN IOCs
    if event.get("p_any_domain_names") is not None:
        for each_domain in event.get("p_any_domain_names"):
            if each_domain in SUNBURST_FQDN_IOCS:
                return True

    # Check through the IP IOCs
    if event.get("p_any_ip_addresses") is not None:
        for each_ip in event.get("p_any_ip_addresses"):
            if each_ip in SUNBURST_IP_IOCS:
                return True

    return False
