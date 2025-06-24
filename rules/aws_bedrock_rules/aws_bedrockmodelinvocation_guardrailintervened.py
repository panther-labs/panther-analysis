def rule(event):
    if (event.get("operation") != "InvokeModel" and event.get("operation") != "Converse"):
        return False

    stop_reason = event.deep_get("output","outputBodyJSON","stopReason",default="<UNKNOWN REASON>")
    action_reason = event.deep_get("output","outputBodyJSON","amazon-bedrock-trace","guardrail","actionReason",default="<UNKNOWN ACTION REASON>")
        
    return stop_reason =="guardrail_intervened" or action_reason.startswith("Guardrail blocked")

def title(event):
    model_id = event.get("modelId")
    operation_name = event.get("operation")
    account_id = event.get("accountId")
    stop_reason = event.deep_get("output","outputBodyJSON","stopReason",default="<UNKNOWN REASON>")
    action_reason = event.deep_get("output","outputBodyJSON","amazon-bedrock-trace","guardrail","actionReason",default="<UNKNOWN ACTION REASON>")
    if action_reason == "<UNKNOWN ACTION REASON>":
        return f"The model [{model_id}] was invoked with the operation [{operation_name}] by the account [{account_id}]. Stop reason [{stop_reason}]."
    if stop_reason == "<UNKNOWN REASON>":
        return f"The model [{model_id}] was invoked with the operation [{operation_name}] by the account [{account_id}]. Action reason [{action_reason}]."
