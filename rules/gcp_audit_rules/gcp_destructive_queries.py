DESTRUCTIVE_STATEMENTS = ["UPDATE", "DELETE", "DROP_TABLE", "ALTER_TABLE", "TRUNCATE_TABLE"]


def rule(event):
    if all(
        [
            event.deep_get("resource", "type", default="<RESOURCE_NOT_FOUND>").startswith(
                "bigquery"
            ),
            event.deep_get("protoPayload", "metadata", "jobChange", "job", "jobConfig", "type")
            == "QUERY",
            event.deep_get(
                "protoPayload",
                "metadata",
                "jobChange",
                "job",
                "jobConfig",
                "queryConfig",
                "statementType",
                default="<STATEMENT_NOT_FOUND>",
            )
            in DESTRUCTIVE_STATEMENTS,
        ]
    ):
        return True

    if event.deep_get("protoPayload", "metadata", "tableDeletion"):
        return True

    if event.deep_get("protoPayload", "metadata", "datasetDeletion"):
        return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    statement = event.deep_get(
        "protoPayload",
        "metadata",
        "jobChange",
        "job",
        "jobConfig",
        "queryConfig",
        "statementType",
        default="<STATEMENT_NOT_FOUND>",
    )
    table = event.deep_get(
        "protoPayload",
        "metadata",
        "jobChange",
        "job",
        "jobConfig",
        "queryConfig",
        "destinationTable",
    ) or event.deep_get("protoPayload", "metadata", "resourceName", default="<TABLE_NOT_FOUND>")
    return f"GCP: [{actor}] performed a destructive BigQuery [{statement}] query on [{table}]."


def alert_context(event):
    return {
        "query": event.deep_get(
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "query",
            default="<QUERY_NOT_FOUND>",
        ),
        "actor": event.deep_get(
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "statement": event.deep_get(
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "statementType",
            default="<STATEMENT_NOT_FOUND>",
        ),
        "table": event.deep_get(
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "destinationTable",
        )
        or event.deep_get("protoPayload", "metadata", "resourceName", default="<TABLE_NOT_FOUND>"),
    }
