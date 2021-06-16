def rule(event):
    return event.get("action") == "repo.created"

def title(event):
    return (
    # TODO: update the visibility 
      f"Repository [{event.get('repository', '<UNKNOWN_REPO>')}] created with visibility [{event.get('')}]"
    )
