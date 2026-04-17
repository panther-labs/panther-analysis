def rule(event):
    return all(
        [
            event.deep_get("resource", "type", default="") == "http_load_balancer",
            event.deep_get("jsonPayload", "statusDetails", default="")
            == "handled_by_identity_aware_proxy",
            not any(
                [
                    str(event.deep_get("httprequest", "status", default=000)).startswith("2"),
                    str(event.deep_get("httprequest", "status", default=000)).startswith("3"),
                ]
            ),
        ]
    )


def title(event):
    source = event.deep_get("jsonPayload", "remoteIp", default="<SRC_IP_NOT_FOUND>")
    request_url = event.deep_get("httprequest", "requestUrl", default="<REQUEST_URL_NOT_FOUND>")
    return f"GCP: Request Violating IAP controls from [{source}] to [{request_url}]"
