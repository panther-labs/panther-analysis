def rule(event):
    # EC2 Volume snapshot made public
    if event['eventName'] == 'ModifySnapshotAttribute':
        parameters = event.get('requestParameters', {})
        if parameters.get('attributeType') != 'CREATE_VOLUME_PERMISSION':
            return False

        items = parameters.get('createVolumePermission',
                               {}).get('add', {}).get('items', [])
        for item in items:
            if item.get('group') == 'all':
                return True
        return False

    # RDS snapshot made public
    if event['eventName'] == 'ModifyDBClusterSnapshotAttribute':
        return 'all' in event.get('requestParemeters',
                                  {}).get('valuesToAdd', [])

    return False
