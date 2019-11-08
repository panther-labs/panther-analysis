import argparse
from collections import defaultdict
from datetime import datetime
import importlib.util
import json
import logging
import os
import shutil
import sys
from typing import Any, Iterator, Tuple, Dict

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


def test_policies(args: argparse.Namespace) -> Tuple[int, list]:
    """Runs tests on each Policy as defined in their specification.

    Args:
        args: The populated Argparse namespace with parsed command-line arguments.

    Returns:
        A tuple of the return code, and a list of tuples containing invalid specs and their error.
    """
    return_code = 0
    invalid_specs = []
    failed_tests = defaultdict(list)
    passed_tests = defaultdict(list)
    logging.info('Testing Policies in %s\n', args.policies)

    specs = list(load_policy_specs(args.policies))
    for index, (policy_spec_filename, dir_name,
                policy_spec) in enumerate(specs):
        if policy_spec.get('PolicyID') != 'aws_globals':
            continue
        module, load_err = load_module(
            os.path.join(dir_name, policy_spec['Filename']))
        # If the module could not be loaded, continue to the next
        if load_err:
            invalid_specs.append((policy_spec_filename, load_err))
            break
        sys.modules['aws_globals'] = module
        del specs[index]

    for policy_spec_filename, dir_name, policy_spec in specs:
        try:
            SPEC_SCHEMA.validate(policy_spec)
        except (SchemaError, SchemaMissingKeyError, SchemaForbiddenKeyError,
                SchemaUnexpectedTypeError) as err:
            invalid_specs.append((policy_spec_filename, err))
            continue

        print(policy_spec['PolicyID'])

        # Check if the PolicyID has already been loaded
        if policy_spec['PolicyID'] in failed_tests or policy_spec[
                'PolicyID'] in passed_tests:
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

        if policy_spec['AnalysisType'] == 'policy':
            run_func = module.policy
        elif policy_spec['AnalysisType'] == 'rule':
            run_func = module.rule

        for unit_test in policy_spec['Tests']:
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
                failed_tests[policy_spec['PolicyID']].append(unit_test['Name'])
            else:
                passed_tests[policy_spec['PolicyID']].append(unit_test['Name'])
            print('\t[{}] {}'.format(test_result, unit_test['Name']))
        print('')

    if failed_tests:
        return_code = 1
        logging.error("Failed Tests:\n")
        for policy_id, failed_tests in failed_tests.items():
            print("{}\n\t{}\n".format(policy_id, failed_tests))

    if invalid_specs:
        return_code = 1
        logging.error("Invalid Policy Files:\n")
        for spec_filename, spec_error in invalid_specs:
            print("{}\n\t{}\n".format(spec_filename, spec_error))

    return return_code, invalid_specs


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

    return parser


def run() -> None:
    logging.basicConfig(format='[%(levelname)s]: %(message)s',
                        level=logging.DEBUG)

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
