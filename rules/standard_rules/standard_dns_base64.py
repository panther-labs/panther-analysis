from panther_base_helpers import defang_ioc, is_base64

DECODED = ""


def rule(event):
    query = event.udm("dns_query")
    # If there is no query present (or the appropriate data model is missing) don't alert
    if not query:
        return False
    args = query.split(".")

    # Check if Base64 encoded arguments are present in the command line
    for arg in args:
        # pylint: disable=global-statement
        global DECODED
        DECODED = is_base64(arg)
        if DECODED:
            return True

    return False


def title(event):
    defang_query = defang_ioc(event.udm("dns_query"))
    return f'Base64 encoded query detected from [{event.udm("source_ip")}], [{defang_query}]'


def alert_context(event):
    context = {}
    context["source ip"] = event.udm("source_ip")
    context["defanged query"] = defang_ioc(event.udm("dns_query"))
    context["decoded url part"] = DECODED
    return context
