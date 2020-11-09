import argparse
import boto3
import logging
import json
from os import path
import yaml

REGION = 'us-east-2'
ACCOUNT_ID = '185324533555'
QUEUE_NAME = 'panther-source-e9fa3b38-45c8-40ba-a1b2-e06d8468722f'
QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/{AccountID}/{QueueName}'


def send_message(client, body):
    return client.send_message(
        QueueUrl=QUEUE_URL.format(AccountID=ACCOUNT_ID, QueueName=QUEUE_NAME),
        MessageBody=json.dumps(body)
    )


def main(filename):
    if not path.exists(filename):
        logging.error('File does not exist: %s', filename)
        return False

    client = boto3.client('sqs', region_name=REGION)

    with open(filename) as file:
        data = yaml.load(file, Loader=yaml.FullLoader)

    if data['Type'] == 'AWS.CloudTrail':
        logging.info('Sending %d CloudTrail logs...', len(data['Logs']))
        for indx, log in enumerate(data['Logs']):
            # Wrap the CloudTrail in a 'Records' top-level key
            resp = send_message(client, {'Records': [log]})
            logging.info('\t%d: %s', indx+1, resp['ResponseMetadata']['HTTPStatusCode'])
    else:
        logging.info('Sending %d %s logs...', len(data['Logs']), data['Type'])
        for indx, log in enumerate(data['Logs']):
            resp = send_message(client, log)
            logging.info('%d: %s', indx+1, resp['ResponseMetadata']['HTTPStatusCode'])
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send test data to Panther.')
    parser.add_argument('--file', help='the yml file with test data')
    args = parser.parse_args()

    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S')

    main(args.file)
