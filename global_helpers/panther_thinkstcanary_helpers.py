def additional_details(event):
    details = event.get("AdditionalDetails", [])
    return {detail[0]: detail[-1] for detail in details}
