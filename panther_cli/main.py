'''
Copyright 2020 Panther Labs Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import argparse
import base64
from datetime import datetime
import importlib.util
from collections import defaultdict
from importlib.abc import Loader
import json
import logging
import os
import shutil
import sys
from typing import Any, Callable, DefaultDict, Dict, Iterator, List, Tuple
import boto3
from schema import (Optional, Or, Schema, SchemaError, SchemaMissingKeyError,
                    SchemaForbiddenKeyError, SchemaUnexpectedTypeError)
import yaml


class TestCase():

    def __init__(self, data: Dict[str, Any], schema: str) -> None:
        self._data = data
        self.schema = schema

    def __getitem__(self, arg: str) -> Any:
        return self._data.get(arg, None)

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def get(self, arg: str, default: Any = None) -> Any:
        return self._data.get(arg, default)


SPEC_SCHEMA = Schema(
    {
        'AnalysisType':
            Or("policy", "rule"),
        'Enabled':
            bool,
        'Filename':
            str,
        'PolicyID':
            str,
        'ResourceTypes': [str],
        'Severity':
            Or("Info", "Low", "Medium", "High", "Critical"),
        Optional('ActionDelaySeconds'):
            int,
        Optional('AlertFormat'):
            str,
        Optional('AutoRemediationID'):
            str,
        Optional('AutoRemediationParameters'):
            object,
        Optional('Description'):
            str,
        Optional('DisplayName'):
            str,
        Optional('Reference'):
            str,
        Optional('Runbook'):
            str,
        Optional('Suppressions'): [str],
        Optional('Tags'): [str],
        Optional('Tests'): [{
            'Name': str,
            'ResourceType': str,
            'ExpectedResult': bool,
            'Resource': object
        }]
    },
    ignore_extra_keys=False)


def load_module(filename: str) -> Tuple[Any, Any]:
    """Loads the Policy function module from a file.

    Args:
        filename: The relative path to the file.

    Returns:
        A loaded Python module.
    """
    module_name = filename.split('.')[0]
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    try:
        assert isinstance(spec.loader, Loader)  #nosec
        spec.loader.exec_module(module)
    except FileNotFoundError as err:
        print('\t[ERROR] File not found, skipping\n')
        return None, err
    return module, None


def load_policy_specs(directory: str) -> Iterator[Tuple[str, str, Any]]:
    """Loads the Policy function module from a file.

    Args:
        directory: The relativie path to Panther policies.

    Yields:
        A tuple of the relative filepath, directory name, and loaded policy specification dict.
    """
    for dir_name, _, file_list in os.walk(directory):
        for filename in sorted(file_list):
            spec_filename = os.path.join(dir_name, filename)
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                with open(spec_filename, 'r') as spec_file_obj:
                    yield spec_filename, dir_name, yaml.safe_load(spec_file_obj)
            if filename.endswith('.json'):
                with open(spec_filename, 'r') as spec_file_obj:
                    yield spec_filename, dir_name, json.load(spec_file_obj)


def datetime_converted(obj: Any) -> Any:
    """A helper function for dumping spec files to JSON.

    Args:
        obj: Any object to convert.

    Returns:
        A string representation of the datetime.
    """
    if isinstance(obj, datetime):
        return obj.__str__()
    return obj


def zip_policies(args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, and then archives all policies into a local zip file.

    Returns 1 if the policy test or validation fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    return_code, _ = test_policies(args)

    if return_code == 1:
        return return_code, ''

    logging.info('Zipping policies in %s to %s', args.policies,
                 args.output_path)
    # example: 2019-08-05T18-23-25
    # The colon character is not valid in filenames.
    current_time = datetime.now().isoformat(timespec='seconds').replace(
        ':', '-')
    filename = 'panther-policies'
    return 0, shutil.make_archive(
        os.path.join(args.output_path, '{}-{}'.format(filename, current_time)),
        'zip', args.policies)


def upload_policies(args: argparse.Namespace) -> Tuple[int, str]:
    """Tests, validates, packages, and then uploads all policies into a Panther deployment.

    Returns 1 if the policy tests, validation, or packaging fails.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of return code and the archive filename.
    """
    return_code, archive = zip_policies(args)
    if return_code == 1:
        return return_code, ''

    client = boto3.client('lambda')

    with open(archive, 'rb') as analysis_zip:
        zip_bytes = analysis_zip.read()
        payload = {
            'resource':
                '/upload',
            'HTTPMethod':
                'POST',
            'Body':
                json.dumps({
                    'Data': base64.b64encode(zip_bytes).decode('utf-8'),
                    'UserID': 'c273fd96-88d0-41c4-a74e-941e17832915',
                }),
        }

        logging.info('Uploading pack to Panther')
        response = client.invoke(FunctionName='panther-analysis-api',
                                 InvocationType='RequestResponse',
                                 LogType='None',
                                 Payload=json.dumps(payload))

        response_str = response['Payload'].read().decode('utf-8')
        response_payload = json.loads(response_str)

        if response_payload['statusCode'] != 200:
            return 1, ''

        body = json.loads(response_payload['body'])
        logging.info('Upload success.')
        logging.info(
            '\n\t%d new policies\n\t%d modified policies\n\t%d new rules\n\t%d modified rules',
            body['newPolicies'], body['modifiedPolicies'], body['newRules'],
            body['modifiedRules'])

    return 0, ''


def test_policies(args: argparse.Namespace) -> Tuple[int, list]:
    """Imports each Policy/Rule and runs their tests.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    invalid_specs = []
    failed_tests: DefaultDict[str, list] = defaultdict(list)
    tests: List[str] = []
    logging.info('Testing Policies in %s\n', args.policies)

    # First import the globals file
    specs = list(load_policy_specs(args.policies))
    for policy_spec_filename, dir_name, policy_spec in specs:
        if policy_spec.get('PolicyID') != 'aws_globals':
            continue
        module, load_err = load_module(
            os.path.join(dir_name, policy_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((policy_spec_filename, load_err))
            break
        sys.modules['aws_globals'] = module

    # Next import each policy and run its tests
    for policy_spec_filename, dir_name, policy_spec in specs:
        if policy_spec.get('PolicyID') == 'aws_globals':
            continue

        try:
            SPEC_SCHEMA.validate(policy_spec)
        except (SchemaError, SchemaMissingKeyError, SchemaForbiddenKeyError,
                SchemaUnexpectedTypeError) as err:
            invalid_specs.append((policy_spec_filename, err))
            continue

        print(policy_spec['PolicyID'])

        # Check if the PolicyID has already been loaded
        if policy_spec['PolicyID'] in tests:
            print('\t[ERROR] Conflicting PolicyID\n')
            invalid_specs.append(
                (policy_spec_filename,
                 'Conflicting PolicyID: {}'.format(policy_spec['PolicyID'])))
            continue

        module, load_err = load_module(
            os.path.join(dir_name, policy_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((policy_spec_filename, load_err))
            continue

        tests.append(policy_spec['PolicyID'])
        if policy_spec['AnalysisType'] == 'policy':
            run_func = module.policy
        elif policy_spec['AnalysisType'] == 'rule':
            run_func = module.rule
        failed_tests = run_tests(policy_spec, run_func, failed_tests)
        print('')

    for policy_id in failed_tests:
        print("Failed: {}\n\t{}\n".format(policy_id, failed_tests[policy_id]))

    for spec_filename, spec_error in invalid_specs:
        print("Invalid: {}\n\t{}\n".format(spec_filename, spec_error))

    return int(bool(failed_tests or invalid_specs)), invalid_specs


def run_tests(policy: Dict[str, Any], run_func: Callable[[TestCase], bool],
              failed_tests: DefaultDict[str, list]) -> DefaultDict[str, list]:

    for unit_test in policy['Tests']:
        try:
            test_case = TestCase(unit_test['Resource'],
                                 unit_test['ResourceType'])
            result = run_func(test_case)
        except KeyError as err:
            print("KeyError: {0}".format(err))
            continue
        test_result = 'PASS'
        if result != unit_test['ExpectedResult']:
            test_result = 'FAIL'
            failed_tests[policy['PolicyID']].append(unit_test['Name'])
        print('\t[{}] {}'.format(test_result, unit_test['Name']))

    return failed_tests


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=
        'Panther CLI: A tool for writing, testing, and packaging Panther Policies/Rules',
        prog='panther_cli')
    parser.add_argument('--version',
                        action='version',
                        version='panther-cli 0.1.4')
    subparsers = parser.add_subparsers()

    test_parser = subparsers.add_parser(
        'test', help='Validate policy specifications and run policy tests.')
    test_parser.add_argument('--policies',
                             type=str,
                             help='The relative path to Panther policies.',
                             required=True)
    test_parser.set_defaults(func=test_policies)

    zip_parser = subparsers.add_parser(
        'zip',
        help='Create an archive of local policies for uploading to Panther.')
    zip_parser.add_argument('--policies',
                            type=str,
                            help='The relative path to Panther policies.',
                            required=True)
    zip_parser.add_argument('--output-path',
                            type=str,
                            help='The path to write zipped policies to.',
                            required=True)
    zip_parser.set_defaults(func=zip_policies)

    upload_parser = subparsers.add_parser(
        'upload', help='Upload specified policies to a Panther deployment.')
    upload_parser.add_argument('--policies',
                               type=str,
                               help='The relative path to Panther policies.',
                               required=True)
    upload_parser.add_argument('--output-path',
                               default='.',
                               type=str,
                               help='The relative path to Panther policies.',
                               required=False)
    upload_parser.set_defaults(func=upload_policies)

    return parser


def run() -> None:
    logging.basicConfig(format='[%(levelname)s]: %(message)s',
                        level=logging.INFO)

    parser = setup_parser()
    args = parser.parse_args()
    try:
        return_code, out = args.func(args)
    except AttributeError:
        parser.print_help()
        sys.exit(1)

    if return_code == 1:
        if out:
            logging.error(out)
    elif return_code == 0:
        if out:
            logging.info(out)

    sys.exit(return_code)


if __name__ == '__main__':
    run()
