import panther_base_helpers

def rule(event):
    if (event.get("operation") == "InvokeModel" or event.get("operation") == "Converse") and (event.deep_get("output","outputBodyJSON","stopReason",default="<UNKNOWN REASON>")=="guardrail_intervened" or event.deep_get("output","outputBodyJSON","amazon-bedrock-trace","guardrail","actionReason",default="<UNKNOWN ACTION REASON>").startswith("Guardrail blocked") or event.deep_get("output","outputBodyJson","usage""totalTokens",default=0)>4000):
        return True
    return False

def title(event):
    model_id = event.get("modelId")
    operation_name = event.get("operation")
    account_id = event.get("accountId")
    stop_reason = event.deep_get("output","outputBodyJSON","stopReason",default="<UNKNOWN REASON>")
    action_reason = event.deep_get("output","outputBodyJSON","amazon-bedrock-trace","guardrail","actionReason",default="<UNKNOWN ACTION REASON>")
    return f"The model [{model_id}] was invoked with the operation [{operation_name}] by the account [{account_id}]. Stop reason [{stop_reason}]. Action reason [{action_reason}]"