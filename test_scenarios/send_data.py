import argparse
import boto3
import logging
import json
from os import path
import yaml

QUEUE_URL = 'https://sqs.{Region}.amazonaws.com/{AccountID}/{QueueName}'
FLOW_LOG_HEADER = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'


def send_message(client, queue_url, message, message_format):
    if message_format == 'raw':
        message_str = message
    elif message_format == 'json':
        message_str = json.dumps(message)
    return client.send_message(QueueUrl=queue_url, MessageBody=message_str)


def process_file(client, queue_url, logs, log_type, message_format):
    if log_type == 'AWS.CloudTrail':
        logging.info('Sending %d CloudTrail logs...', len(logs))
        for indx, log in enumerate(logs):
            # Wrap the CloudTrail in a 'Records' top-level key
            resp = send_message(client, queue_url, {'Records': [log]},
                                message_format)
            logging.debug('Message [%d] response: %s', indx + 1,
                          resp['ResponseMetadata']['HTTPStatusCode'])
        return

    if log_type == 'AWS.VPCFlow':
        logging.debug('Sending VPC Flow log header')
        resp = send_message(client, queue_url, FLOW_LOG_HEADER, 'raw')
        logging.debug('Message [1] response: %s',
                      resp['ResponseMetadata']['HTTPStatusCode'])

    logging.info('Sending %d %s logs...', len(logs), log_type)
    for indx, log in enumerate(logs):
        resp = send_message(client, queue_url, log, message_format)
        logging.debug('Message [%d] response: %s', indx + 1,
                      resp['ResponseMetadata']['HTTPStatusCode'])


def main(args):
    if not path.exists(args.file):
        logging.error('File does not exist: %s', args.file)
        return False

    with open(args.file) as file:
        data = yaml.load(file, Loader=yaml.FullLoader)

    process_file(
        boto3.client('sqs', region_name=args.region),
        QUEUE_URL.format(AccountID=args.account_id, QueueName=args.queue_name),
        data.get('Logs', []), data.get('LogType', ''),
        data.get('Format', 'json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send test data to Panther.')
    parser.add_argument('--file',
                        help='the yml file with test data',
                        required=True)
    parser.add_argument('--account-id',
                        help='the AWS account ID of the Panther deployment',
                        required=True)
    parser.add_argument('--queue-name',
                        help='the SQS Queue of the Panther source',
                        required=True)
    parser.add_argument(
        '--region',
        help='the region of the SQS Queue of the Panther source',
        required=True)
    args = parser.parse_args()

    logging.basicConfig(format='[%(asctime)s %(levelname)-8s] %(message)s',
                        level=logging.INFO,
                        datefmt='%Y-%m-%d %H:%M:%S')

    main(args)
