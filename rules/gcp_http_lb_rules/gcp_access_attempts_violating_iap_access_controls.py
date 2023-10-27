from panther_base_helpers import deep_get


def rule(event):
    return all(
        [
            deep_get(event, "resource", "type", default="") == "http_load_balancer",
            deep_get(event, "jsonPayload", "statusDetails", default="")
            == "handled_by_identity_aware_proxy",
            not any(
                [
                    str(deep_get(event, "httprequest", "status", default=000)).startswith("2"),
                    str(deep_get(event, "httprequest", "status", default=000)).startswith("3"),
                ]
            ),
        ]
    )


def title(event):
    source = deep_get(event, "jsonPayload", "remoteIp", default="<SRC_IP_NOT_FOUND>")
    request_url = deep_get(event, "httprequest", "requestUrl", default="<REQUEST_URL_NOT_FOUND>")
    return f"GCP: Request Violating IAP controls from [{source}] to [{request_url}]"
