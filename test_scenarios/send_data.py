import argparse
import boto3
from datetime import datetime, date, timezone
import gzip
from io import BytesIO
import json
import logging
from os import path
import uuid
import yaml

# FIXME: refactor and generalize this to more log types for more scenarios

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
        boto3.client('s3', region_name=args.region),
        args.bucket_name,
        data.get('Logs', []),
        data.get('LogType', ''),
        data.get('Format', 'jsonl'))

def process_file(event_time_shift, client, bucket_name, logs, log_type, log_format):
    # these 2 are special
    if log_type == 'AWS.CloudTrail':
        process_cloudtrail(event_time_shift, client, bucket_name, logs, log_type)
        return
    if log_type == 'AWS.VPCFlow':
        process_vpcflow(event_time_shift, client, bucket_name, logs, log_type)
        return

    # nothing special to do ...
    if log_format == 'jsonl':
        process_any_jsonl(event_time_shift, client, bucket_name, logs, log_type)
        return
    if log_format == 'raw':
       process_any_raw(event_time_shift, client, bucket_name, logs, log_type)
       return

    raise Exception('unknown log format: ' + log_format)

def process_cloudtrail(event_time_shift, client, bucket_name, logs, log_type):
    logs = time_shift_json_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] CloudTrail logs...', len(logs))
    # Wrap the CloudTrail in a 'Records' top-level key
    resp = write_s3(client, bucket_name, {'Records': logs}, 'json')
    logging.debug('Response: %s', resp['ResponseMetadata']['HTTPStatusCode'])

FLOW_LOG_HEADER = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'
def process_vpcflow(event_time_shift, client, bucket_name, logs, log_type):
    logs = time_shift_vpcflow_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] %s logs...', len(logs), log_type)
    resp = write_s3(client, bucket_name, [FLOW_LOG_HEADER]+logs, 'raw')
    logging.debug('Response: %s', resp['ResponseMetadata']['HTTPStatusCode'])

def process_any_jsonl(event_time_shift, client, bucket_name, logs, log_type):
    logs = time_shift_json_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] %s logs...', len(logs), log_type)
    resp = write_s3(client, bucket_name, logs, 'jsonl')
    logging.debug('Response: %s', resp['ResponseMetadata']['HTTPStatusCode'])

def process_any_raw(event_time_shift, client, bucket_name, logs, log_type):
    logs = time_shift_raw_logs(event_time_shift, logs, log_type)
    logging.info('Sending [%d] %s logs...', len(logs), log_type)
    resp = write_s3(client, bucket_name, logs, 'raw')
    logging.debug('Response: %s', resp['ResponseMetadata']['HTTPStatusCode'])

def write_s3(client, bucket_name, logs, format):
    if format == 'raw':
        data = "\n".join(logs)
    elif format == 'json':
        data = json.dumps(logs) + "\n"
    elif format == 'jsonl':
        data = ''
        for log in logs:
            data += json.dumps(log) + "\n"
    data_stream = BytesIO()
    writer = gzip.GzipFile(fileobj=data_stream, mode='wb')
    writer.write(data.encode('utf-8'))
    writer.close()
    data_stream.seek(0)
    return client.put_object(Bucket=bucket_name, ContentType='gzip', Body=data_stream, Key=str(uuid.uuid4())+".gz")

def time_shift_json_logs(event_time_shift, logs, log_type):
    shifted_logs = []
    event_time = get_event_time(log_type)
    event_time_attr = event_time['attr']
    event_time_format = event_time['format']
    for log in logs:
        log_event_time = datetime.strptime(log[event_time_attr], event_time_format)
        log_event_time += event_time_shift
        log[event_time_attr] = log_event_time.strftime(event_time_format)
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
        log = ' '.join(log)
        shifted_logs.append(log)
    return shifted_logs

def time_shift_vpcflow_logs(event_time_shift, logs, log_type):
    shifted_logs = []
    start_time_index = 10
    end_time_index = 11
    for log in logs:
        log = log.split(' ')

        log_event_time = datetime.fromtimestamp(int(log[start_time_index]))
        log_event_time += event_time_shift
        log[start_time_index] = str(int(log_event_time.timestamp()))

        log_event_time = datetime.fromtimestamp(int(log[end_time_index]))
        log_event_time += event_time_shift
        log[end_time_index] = str(int(log_event_time.timestamp()))

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
    parser.add_argument('--bucket-name',
                        help='the S3 bucket name of the Panther source',
                        required=True)
    parser.add_argument('--region',
                        help='the region of the SQS Queue of the Panther source',
                        required=True)
    parser.add_argument('--compromise-datetime',
                        help='the datetime of the compromise UTC in iso format',
                        type=datetime.fromisoformat,
                        required=True)
    parser.add_argument('--panther-compromise-datetime',
                         help='the datetime to shift all events from the compromise date UTC in iso format (defaults to now)',
                         type=datetime.fromisoformat,
                         default=datetime.now(timezone.utc),
                         required=False)
    args = parser.parse_args()

    logging.basicConfig(format='[%(asctime)s %(levelname)-8s] %(message)s',
                        level=logging.INFO,
                        datefmt='%Y-%m-%d %H:%M:%S')

    main(args)
