import argparse
import csv
import json
import os
import logging
import yaml


def load_csv_logs(filename):
    logs = []
    p_fields = set()
    with open(filename, 'r' ) as fi:
        reader = csv.DictReader(fi)
        for line_num, line in enumerate(reader):
            # Get the full list of p_ fields in this particular log type
            if line_num == 0:
                for key in line:
                    if key.startswith('p_'):
                        p_fields.add(key)
            # Pop the p_any fields off the record so the reclassify
            for p_field in p_fields:
                line.pop(p_field)
            logs.append(line)
    return json.loads(json.dumps(logs))


def load_json_logs(filename):
    logs = []
    with open(filename) as fi:
        for line_num, line in enumerate(fi):
            try:
                json_line = json.loads(line)
            except json.JSONDecodeError:
                logging.error("non-JSON line [%s] detected", line_num + 1)
                continue
            panther_keys = set(key for key in json_line.keys() if key.startswith('p_'))
            for key in panther_keys:
                del json_line[key]
            logs.append(json_line)
    return logs


def main(cmdline_args):
    test_data = {
        "LogType": cmdline_args.log_type,
        "Format": cmdline_args.log_format,
    }

    extension = os.path.splitext(cmdline_args.input)[1]
    if extension == '.csv':
        test_data['Logs'] = load_csv_logs(cmdline_args.input)
    elif extension == '.json':
        test_data['Logs'] = load_json_logs(cmdline_args.input)
    else:
        logging.info('unsupported input type: %s', extension)
        return

    with open(cmdline_args.output, "w") as fo:
        yaml.dump(test_data, fo)
    logging.info("Wrote %d example logs to %s", len(test_data['Logs']), cmdline_args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prepare scenario data from JSONL-formatted files."
    )
    parser.add_argument(
        "--input", help="the filename", required=True)
    parser.add_argument(
        "--output", help="the YAML scenario filename", required=True)
    parser.add_argument(
        "--log-type", help="the test scenario log type (e.g. AWS.CloudTrail)", required=True
    )
    parser.add_argument(
        "--log-format",
        help="the format to write test_data out to S3 (json, jsonl, raw)",
        required=True,
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="[%(asctime)s %(levelname)s] %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    main(args)
