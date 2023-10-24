from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all AzureSignIn detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    #  including a single tenant
    #    1. events from only this tenantId
    #    2. events that have an undefined tenantId
    #
    #
    # # example: event['tenantId']
    # # if tenantId were missing, we want default behavior to be to alert on this event.
    # tenant_id = deep_get(event, "tenantId", default="")
    # return event_origin in ["333333eb-a222-33cc-9baf-4a1111111111", ""]
    #
    return True
