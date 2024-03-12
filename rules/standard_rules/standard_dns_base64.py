from base64 import b64decode
from binascii import Error as AsciiError

from panther_base_helpers import defang_ioc

DECODED = ""


def rule(event):
    args = event.udm("dns_query").split(".")

    for arg in args:
        try:
            # Check if the matched string can be decoded back into ASCII
            global DECODED
            DECODED = b64decode(arg).decode("ascii")
            if len(DECODED) > 0:
                return True
        except AsciiError:
            continue
        except UnicodeDecodeError:
            continue

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
