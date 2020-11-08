import boto3
import json
import yaml

REGION = 'us-east-2'
ACCOUNT_ID = ''
QUEUE_NAME = ''
QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/{AccountID}/{QueueName}'
FILE = r'threat_hunting_proper.yaml'


def send_message(client, body):
    return client.send_message(
        QueueUrl=QUEUE_URL.format(AccountID=ACCOUNT_ID, QueueName=QUEUE_NAME),
        MessageBody=json.dumps(body)
    )


def main():
    client = boto3.client('sqs', region_name=REGION)

    with open(FILE) as file:
        data = yaml.load(file, Loader=yaml.FullLoader)

    if data['Type'] == 'AWS.CloudTrail':
        print('Sending {} CloudTrail Logs...'.format(len(data['Logs'])))
        for indx, log in enumerate(data['Logs']):
            resp = send_message(client, {'Records': [log]})
            print('\t{}: {}'.format(indx+1, resp['ResponseMetadata']['HTTPStatusCode']))

if __name__ == '__main__':
    main()
