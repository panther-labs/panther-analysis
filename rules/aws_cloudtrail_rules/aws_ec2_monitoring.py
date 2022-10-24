from panther_base_helpers import deep_get

# AWS CloudTrail API eventNames for EC2 Instance Creation or Start
ec2_instance = [
    'RunInstances',
    'RunScheduledInstances',
    'StartInstances'
]

# AWS CloudTrail API eventNames for EC2 Image Creation
ec2_image = [
    'CopyFpgaImage',
    'CopyImage',
    'CreateFpgaImage',
    'CreateImage',
    'CreateRestoreImageTask',
    'CreateStoreImageTask',
    'ImportImage'
]

def rule(event):

    # Exclude automation and dry run operations
    if deep_get(event, 'userIdentity', 'invokedBy') == 'autoscaling.amazonaws.com':
        return False
    
    if event.get('errorCode') == 'Client.DryRunOperation':
        return False

    # Check for Instance Creation or Start
    if event.get('eventName') in ec2_instance:
        return True

    # Check for Image Creation
    if event.get('eventName') in ec2_image:
        return True

def title(event):
    return f"{deep_get(event, 'userIdentity', 'sessionContext', 'sessionIssuer', 'userName')} triggered a [{event.get('eventName')}] event within AWS Account ID: [{event.get('recipientAccountId')}]"
