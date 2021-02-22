import argparse
import logging
import json
import yaml


def main(args):
    test_data = {"LogType": args.log_type, "Format": args.log_format, "Logs": []}

    with open(args.input) as fi:
        append_count = 0
        for line_num, line in enumerate(fi):
            try:
                json_line = json.loads(line)
            except json.JSONDecodeError:
                logging.error("non-JSON line [%s] detected", line_num + 1)
                continue
            test_data["Logs"].append(json_line)
            append_count += 1

    with open(args.output, "w") as fo:
        yaml.dump(test_data, fo)

    logging.info("Wrote %d example logs to %s", append_count, args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prepare scenario data from JSONL-formatted files."
    )
    parser.add_argument("--input", help="the JSONL filename", required=True)
    parser.add_argument("--output", help="the YAML scenario filename", required=True)
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
