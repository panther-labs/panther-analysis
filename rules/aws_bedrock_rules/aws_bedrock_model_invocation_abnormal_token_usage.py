import panther_base_helpers

def rule(event):
    # Only process InvokeModel and Converse operations
    if event.get("operation") not in ["InvokeModel", "Converse"]:
        return False

    #retrieve the necessary values from the logs
    token_usage = event.deep_get("output", "outputBodyJson", "usage", "totalTokens", default=0)
    model_id = event.get("modelId", default="")
    
    # Get the appropriate threshold for each model
    if "haiku" in model_id:
        threshold = 3000
    elif "sonnet" in model_id:
        threshold = 4000
    elif "opus" in model_id:
        threshold = 5000
    else:
        threshold = 4000 #default threshold
    
    # Check for abnormal token usage
    if token_usage > threshold:
        return True
    
    # Flag unusual token patterns (high usage with no actual output)
    output_tokens = event.deep_get("output", "outputBodyJson", "usage", "outputTokens", default=0)
    if token_usage > 1000 and output_tokens == 0:
        return True
    
    return False

def title(event):
    model_id = event.get("modelId", default="unknown")
    operation_name = event.get("operation", default="unknown")
    account_id = event.get("accountId", default="unknown")
    token_usage = event.deep_get("output", "outputBodyJson", "usage", "totalTokens", default=0)
    
    title_parts = [
        f"Abnormal token usage detected: {token_usage} tokens",
        f"Model: {model_id}",
        f"Operation: {operation_name}",
        f"Account: {account_id}"
    ]
    
    return " | ".join(title_parts)
    