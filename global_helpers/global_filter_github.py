from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all github detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    #   ignoring all github organization logs except for
    #   the production github organization.
    # If you're ingesting GitHub Enterprise Logs with multiple
    #   orgs, this may help to keep your detections running
    #   on the production orgs
    #
    #
    # # not all github enterprise events have org
    # # example: enterprise.self_hosted_runner_online
    # org = deep_get(event, "org", default="")
    # return org in ["my-prod-org", ""]
    #
    return True
