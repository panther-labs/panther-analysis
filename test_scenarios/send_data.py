import argparse
from datetime import datetime, date, timezone
import boto3
import logging
import json
from os import path
import yaml

QUEUE_URL = 'https://sqs.{Region}.amazonaws.com/{AccountID}/{QueueName}'
FLOW_LOG_HEADER = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'

def main(args):
    if not path.exists(args.file):
        logging.error('File does not exist: %s', args.file)
        return False

    with open(args.file) as file:
        data = yaml.load(file, Loader=yaml.FullLoader)

    logging.info('Loading file %s (%s)', args.file, data.get('LogType', ''))

    # ensure UTC
    args.panther_compromise_datetime = args.panther_compromise_datetime.replace(tzinfo=timezone.utc)
    args.compromise_datetime = args.compromise_datetime.replace(tzinfo=timezone.utc)

    process_file(
        args.panther_compromise_datetime - args.compromise_datetime,
        boto3.client('sqs', region_name=args.region),
        QUEUE_URL.format(AccountID=args.account_id,
                         Region=args.region,
                         QueueName=args.queue_name),
                         data.get('Logs', []),
                         data.get('LogType', ''),
                         data.get('Format', 'json'))

def process_file(event_time_shift, client, queue_url, logs, log_type, message_format):
    # these 2 are special
    if log_type == 'AWS.CloudTrail':
        process_cloudtrail(event_time_shift, client, queue_url, logs, log_type)
        return
    if log_type == 'AWS.VPCFlow':
        process_vpcflow(event_time_shift, client, queue_url, logs, log_type)
        return

    # nothing special to do
    if message_format == 'json':
        process_any_json(event_time_shift, client, queue_url, logs, log_type)
        return
    if message_format == 'raw':
       process_any_raw(event_time_shift, client, queue_url, logs, log_type)
       return

    return

def process_cloudtrail(event_time_shift, client, queue_url, logs, log_type):
    logs = time_shift_json_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] CloudTrail logs...', len(logs))
    # Wrap the CloudTrail in a 'Records' top-level key
    resp = send_message(client, queue_url, {'Records': logs}, 'json')
    logging.debug('Response: %s', resp['ResponseMetadata']['HTTPStatusCode'])

def process_vpcflow(event_time_shift, client, queue_url, logs, log_type):
    logs = time_shift_vpcflow_logs(event_time_shift, logs, log_type)
    logging.debug('Sending VPC Flow log header')
    resp = send_message(client, queue_url, FLOW_LOG_HEADER, 'raw')
    logging.debug('Response: %s', resp['ResponseMetadata']['HTTPStatusCode'])

    logging.info('Sending [%d] %s logs...', len(logs), log_type)
    for indx, log in enumerate(logs):
        resp = send_message(client, queue_url, log, 'raw')
        logging.debug('Message [%d] response: %s', indx + 1, resp['ResponseMetadata']['HTTPStatusCode'])

def process_any_json(event_time_shift, client, queue_url, logs, log_type):
    logs = time_shift_json_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] %s logs...', len(logs), log_type)
    for indx, log in enumerate(logs):
        resp = send_message(client, queue_url, log, 'json')
        logging.debug('Message [%d] response: %s', indx + 1, resp['ResponseMetadata']['HTTPStatusCode'])

def process_any_raw(event_time_shift, client, queue_url, logs, log_type):
    logs = time_shift_raw_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] %s logs...', len(logs), log_type)
    for indx, log in enumerate(logs):
        resp = send_message(client, queue_url, log, 'raw')
        logging.debug('Message [%d] response: %s', indx + 1, resp['ResponseMetadata']['HTTPStatusCode'])

# FIXME: we need to change to S3 files, sqs does not guarantee order of events and VPC flow needs a header to precede
# FIXME: the work around is to push only 1 file per minute maximum and hope for the best
def send_message(client, queue_url, message, message_format):
    if message_format == 'raw':
        message_str = message
    elif message_format == 'json':
        message_str = json.dumps(message)
    return client.send_message(QueueUrl=queue_url, MessageBody=message_str)

# FIXME: event shifting should be in its own file
def time_shift_json_logs(event_time_shift, logs, log_type):
    shifted_logs = []
    event_time = get_event_time(log_type)
    event_time_attr = event_time['attr']
    event_time_format = event_time['format']
    for log in logs:
        log_event_time = datetime.strptime(log[event_time_attr], event_time_format)
        log_event_time += event_time_shift
        log[event_time_attr] = log_event_time.strftime(event_time_format)
        logging.debug("%s %s", log_event_time, log[event_time_attr])
        shifted_logs.append(log)
    return shifted_logs

def time_shift_raw_logs(event_time_shift, logs, log_type):
    shifted_logs = []
    event_time = get_event_time(log_type)
    event_time_index = event_time['index']
    event_time_format = event_time['format']
    for log in logs:
        log = log.split(' ')
        log_event_time = datetime.strptime(log[event_time_index], event_time_format)
        log_event_time += event_time_shift
        log[event_time_index] = log_event_time.strftime(event_time_format)
        logging.debug("%s %s", log_event_time, log[event_time_index])
        log = ' '.join(log)
        shifted_logs.append(log)
    return shifted_logs

def time_shift_vpcflow_logs(event_time_shift, logs, log_type):
    shifted_logs = []
    start_time_index = 10
    end_time_index = 11
    for log in logs:
        log = log.split(' ')

        logging.error("%s",log[start_time_index])
        log_event_time = datetime.fromtimestamp(int(log[start_time_index]))
        log_event_time += event_time_shift
        log[start_time_index] = str(int(log_event_time.timestamp()))
        logging.debug("%s %s", log_event_time, log[start_time_index])

        log_event_time = datetime.fromtimestamp(int(log[end_time_index]))
        log_event_time += event_time_shift
        log[end_time_index] = str(int(log_event_time.timestamp()))
        logging.debug("%s %s", log_event_time, log[end_time_index])

        log = ' '.join(log)
        shifted_logs.append(log)
    return shifted_logs

def get_event_time(log_type):
    if log_type == 'AWS.CloudTrail': #  eventTime: "2020-11-01T08:35:19Z"
        return {'attr': 'eventTime', 'format': '%Y-%m-%dT%H:%M:%SZ'}
    if log_type == 'Okta.SystemLog': # published:
        return {'attr': 'published', 'format': '%Y-%m-%dT%H:%M:%S.%fZ'}
    if log_type == 'AWS.S3ServerAccess': # [03/Nov/2020:04:43:07 +0000]
        return {'index': 2, 'format': '[%d/%b/%Y:%H:%M:%S'}
    raise Exception('unknown logType: ' + log_type)

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
    parser.add_argument('--region',
                        help='the region of the SQS Queue of the Panther source',
                        required=True)
    parser.add_argument('--compromise-datetime',
                        help='the datetime of the compromise UTC in iso format',
                        type=datetime.fromisoformat,
                        required=True)
    parser.add_argument('--panther-compromise-datetime',
                         help='the datetime to shift all events from the compromise date UTC in iso format',
                         type=datetime.fromisoformat,
                         default=datetime.now(timezone.utc),
                         required=False)
    args = parser.parse_args()

    logging.basicConfig(format='[%(asctime)s %(levelname)-8s] %(message)s',
                        level=logging.INFO,
                        datefmt='%Y-%m-%d %H:%M:%S')

    main(args)
