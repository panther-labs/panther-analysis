def rule(event):
    if all(
        [
            event.deep_get("eventtype", default="") == "policy.evaluate_sign_on",
            event.deep_get("target", "displayname", default="") == "Okta Admin Console",
            any(
                [
                    "POSITIVE"
                    in event.deep_get("debugcontext", "debugdata", "behaviors", default=""),
                    "POSITIVE"
                    in event.deep_get(
                        "debugcontext", "debugdata", "logonlysecuritydata", default=""
                    ),
                ]
            ),
        ]
    ):
        return True
    return False
