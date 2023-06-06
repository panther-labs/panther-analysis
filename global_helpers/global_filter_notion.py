from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all Auth0 detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    #  including only:
    #    1. the specific workspace_id mentioned.
    #    2. events where workspace_id is undefined.
    #
    #
    # # example: workspcae_id
    # # if we don't know the workspace_id, we want default behavior to be to alert on this event.
    # workspace_id = deep_get(event, "workspace_id", default="")
    # return workspace_id in ["ea65b016-6abc-4dcf-808b-e000099999999", ""]
    #
    return True
