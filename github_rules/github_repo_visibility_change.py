def rule(event):
    if event.get("action") == "repo.access":
        # TODO: find out what the new access it
        return True
    return False

def title(event):
    return (
    # TODO: update the visibility 
      f"Repository [{event.get('repository', '<UNKNOWN_REPO>')}] visibility changed to [{event.get('')}]"
    )
