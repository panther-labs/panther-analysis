otx_hits = {}
misp_hits = {}


def rule(event):
    lookup_table_name = "AlienVault.OTX"
    global otx_hits
    for k, v in event.items():
        if k.startswith("p_any_") and isinstance(v, list):
            otx_hits[k] = [ioc for ioc in v if event.lookup(lookup_table_name, ioc)]
    return any(otx_hits.values())


def severity(event):
    lookup_table_name = "MISP.WarningListsCIDR"
    global misp_hits
    for k, v in event.items():
        if k.startswith("p_any_") and isinstance(v, list):
            misp_hits[k] = [ioc for ioc in v if event.lookup(lookup_table_name, ioc)]

    if any(misp_hits.values()):
        return "LOW"
    return "HIGH"


def alert_context(event):
    global otx_hits
    global misp_hits
    return otx_hits | misp_hits
