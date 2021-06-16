def rule(event):
    return event.get("action") == "protected_branch.destroy"

def title(event):
    return (
      f"A branch protection was removed from the repository [{event.get('repository', '<UNKNOWN_REPO>')}]"
    )
