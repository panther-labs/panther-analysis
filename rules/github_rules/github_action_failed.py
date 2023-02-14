import json
from unittest.mock import MagicMock

from panther_base_helpers import deep_get, github_alert_context

# The keys for MONITORED_ACTIONS are gh_org/repo_name
# The values for MONITORED_ACTIONS are a list of ["action_names"]
MONITORED_ACTIONS = {}


def rule(event):
    global MONITORED_ACTIONS  # pylint: disable=global-statement
    if isinstance(MONITORED_ACTIONS, MagicMock):
        MONITORED_ACTIONS = json.loads(MONITORED_ACTIONS())  # pylint: disable=not-callable
    repo = deep_get(event, "repo", default="")
    action_name = deep_get(event, "name", default="")
    return all(
        [
            deep_get(event, "action", default="") == "workflows.completed_workflow_run",
            repo in MONITORED_ACTIONS,
            action_name in MONITORED_ACTIONS.get(repo, []),
            deep_get(event, "conclusion", default="") == "failure",
        ]
    )


def title(event):
    repo = deep_get(event, "repo", default="")
    action_name = deep_get(event, "name", default="")
    return f"The GitHub Action [{action_name}] in [{repo}] has failed"


def alert_context(event):
    a_c = github_alert_context(event)
    a_c["action"] = event.get("name", "<NO_ACTION_NAME>")
    a_c["action_run_link"] = (
        f"https://github.com/{a_c.get('repo')}/actions/"
        f"runs/{event.get('workflow_run_id', '<NO_RUN_ID>')}"
    )
    return a_c
