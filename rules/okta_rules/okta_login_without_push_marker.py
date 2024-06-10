# configure this Push marker based on your environment
PUSH_MARKER = "PS_mxzqarw"


def rule(event):
    return not event.deep_get("client", "userAgent", "rawUserAgent", default="").endswith(
        PUSH_MARKER
    )


def title(event):
    return f'{event.deep_get("actor", "displayName")} logged in from device without expected Push marker'
