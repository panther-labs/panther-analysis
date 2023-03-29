from panther_base_helpers import deep_get

DESTRUCTIVE_STATEMENTS = ["UPDATE", "DELETE", "DROP_TABLE", "ALTER_TABLE", "TRUNCATE_TABLE"]


def rule(event):
    if all(
        [
            deep_get(event, "resource", "type", default="<RESOURCE_NOT_FOUND>").startswith(
                "bigquery"
            ),
            deep_get(event, "protopayload", "metadata", "jobChange", "job", "jobConfig", "type")
            == "QUERY",
            deep_get(
                event,
                "protopayload",
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

    if deep_get(event, "protopayload", "metadata", "tableDeletion"):
        return True

    if deep_get(event, "protopayload", "metadata", "datasetDeletion"):
        return True

    return False


def title(event):
    actor = deep_get(
        event, "protopayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    statement = deep_get(
        event,
        "protopayload",
        "metadata",
        "jobChange",
        "job",
        "jobConfig",
        "queryConfig",
        "statementType",
        default="<STATEMENT_NOT_FOUND>",
    )
    table = deep_get(
        event,
        "protopayload",
        "metadata",
        "jobChange",
        "job",
        "jobConfig",
        "queryConfig",
        "destinationTable",
    ) or deep_get(event, "protopayload", "metadata", "resourceName", default="<TABLE_NOT_FOUND>")
    return f"GCP: [{actor}] performed a destructive BigQuery [{statement}] query on [{table}]."


def alert_context(event):
    return {
        "query": deep_get(
            event,
            "protopayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "query",
            default="<QUERY_NOT_FOUND>",
        ),
        "actor": deep_get(
            event,
            "protopayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "statement": deep_get(
            event,
            "protopayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "statementType",
            default="<STATEMENT_NOT_FOUND>",
        ),
        "table": deep_get(
            event,
            "protopayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "destinationTable",
        )
        or deep_get(event, "protopayload", "metadata", "resourceName", default="<TABLE_NOT_FOUND>"),
    }
