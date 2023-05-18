from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all Tines detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    # including only:
    #    1. the specific tenant_id mentioned.
    #    2. events where tenant_id is undefined
    #
    # tenant_id = deep_get(event, "tenant_id", default="")
    # return tenant_id in ["1234", ""]
    #
    return True
