"""
Analyzes all YAML files in the panther-analysis directory and generates a
detections-coverage.json file with markdown indexes in the indexes directory
"""

import collections, json, hashlib, pathlib, yaml, os, itertools


def generate_indexes(directory):
    """
    Generates JSON and Markdown indexes, directory points to the root directory of the repo
    """

    detections = {}
    query_lookup = {}  # Maps QueryNames to their YAML
    logtype_lookup = {
        # Maps tableified names for all LogTypes e.g. onepassword_signinattempt => OnePassword.SignInAttempt this is used to extract "Log Types" from queries
        'crowdstrike_aidmaster': 'Crowdstrike.AIDMaster',
        'snowflake.account_usage': 'Snowflake.AccountUsage'
    }

    for root, subdirectories, files in os.walk(directory):
        for file in files:
            if '/rules' in root or '/policies' in root or '/queries' in root or '/simple_rules' in root or '/correlation_rules' in root:
                if file[-4:] == '.yml':
                    yaml_path = os.path.join(root, file)
                    detection_name = file.replace('.yml', '')
                    detection_yaml = ingest_yaml(yaml_path)
                    if 'QueryName' in detection_yaml:
                        query_lookup[detection_yaml['QueryName']] = detection_yaml
                    if 'RuleID' in detection_yaml:
                        query_lookup[detection_yaml['RuleID']] = detection_yaml
                    if 'LogTypes' in detection_yaml:
                        for log_type in detection_yaml['LogTypes']:
                            logtype_lookup[log_type.lower().replace('.', '_')] = log_type
                    detection_yaml = analyze_yaml(detection_yaml)
                    if 'AnalysisType' not in detection_yaml:
                        continue
                    if detection_yaml['AnalysisType'] in ('datamodel', 'global', 'pack', 'lookup_table'):
                        continue
                    if detection_yaml['DisplayName'] == '' or 'deprecated' in detection_yaml['DisplayName'].lower():
                        continue
                    # May want to revisit this, filtering out signals
                    if 'signal - ' in detection_yaml['DisplayName'].lower():
                        continue
                    # Filter out query names like Query.Snowflake.BruteForceByIp which are often called by other rules
                    if 'query.' in detection_yaml['DisplayName'].lower():
                        continue
                    if 'Description' not in detection_yaml or detection_yaml['Description'] == '':
                        detection_yaml['Description'] = ''
                        # We previously continued here to filter out blank descriptions but now we only filter out the AWS Cloudtrail 2 minute count query that's not enabled by defualt
                        if 'Enabled' not in detection_yaml or detection_yaml['Enabled'] == False:
                            continue

                    detections[detection_name] = detection_yaml
                    detections[detection_name]['YAMLPath'] = yaml_path.replace(str(directory), '').strip('/')  # Relative path from root

    print('Successfully analyzed ' + str(len(detections.keys())) + ' detections!')

    save_website_json(detections, query_lookup, logtype_lookup, pathlib.Path(directory) / 'indexes' / 'detection-coverage.json')
    write_alpha_index(detections, query_lookup, logtype_lookup, pathlib.Path(directory))


def ingest_yaml(path):
    with open(path) as file:
        detection = yaml.full_load(file)
    return detection


def analyze_yaml(detection_yaml):
    rv = {}
    if 'Enabled' in detection_yaml:
        rv["Enabled"] = detection_yaml["Enabled"]

    if 'RuleID' in detection_yaml:
        rv["Name"] = detection_yaml["RuleID"]
    elif 'PolicyID' in detection_yaml:
        rv["Name"] = detection_yaml["PolicyID"]
    elif 'QueryName' in detection_yaml:
        rv["Name"] = detection_yaml["QueryName"]

    if 'AnalysisType' in detection_yaml:
        rv["AnalysisType"] = detection_yaml["AnalysisType"]
    display_name = ''
    if 'QueryName' in detection_yaml:
        display_name = detection_yaml["QueryName"]
    elif 'DisplayName' in detection_yaml:
        display_name = detection_yaml["DisplayName"]
    if display_name == '' and 'RuleID' in detection_yaml:
        display_name = detection_yaml["RuleID"]
    display_name = display_name.replace('--', '~')
    if display_name == '':
        raise Exception("AHH " + repr(detection_yaml))
    if display_name[0] == "'":  # If the whole name is in single quotes remove them
        display_name = display_name.strip("'")
    rv["DisplayName"] = display_name

    if 'ResourceTypes' in detection_yaml:
        rv["LogTypes"] = detection_yaml["ResourceTypes"]
    elif 'LogTypes' in detection_yaml:
        rv["LogTypes"] = detection_yaml["LogTypes"]

    if 'ScheduledQueries' in detection_yaml:
        rv['ScheduledQueries'] = detection_yaml['ScheduledQueries']

    if 'Query' in detection_yaml:
        rv['Query'] = detection_yaml['Query']

    if 'SnowflakeQuery' in detection_yaml:
        rv['SnowflakeQuery'] = detection_yaml['SnowflakeQuery']

    if 'Description' in detection_yaml:
        # strip newlines from end
        rv["Description"] = detection_yaml["Description"].strip()
        # strip newlines embedded in strings
        rv["Description"] = rv["Description"].replace("\n", "").replace("''", "'")

    if 'Tags' in detection_yaml:
        rv["Tags"] = detection_yaml["Tags"]

    if 'Detection' in detection_yaml:
        rv['Detection'] = detection_yaml['Detection']

    return rv


# https://stackoverflow.com/a/44873382
def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def extract_logtypes_from_sql(sql, logtype_lookup):
    logtypes = []
    sql = sql.lower()
    for db_name, log_type in logtype_lookup.items():
        db_name = db_name.lower()
        if db_name in sql and log_type not in logtypes:
            logtypes.append(log_type)
    return logtypes


def extract_log_types_from_yaml(yaml, query_lookup, logtype_lookup):
    if 'LogTypes' in yaml:
        return yaml['LogTypes']
    if 'ScheduledQueries' in yaml:
        for query in yaml['ScheduledQueries']:
            if query in query_lookup:
                query_yaml = query_lookup[query]
                sql = ''
                if 'Query' in query_yaml:
                    sql = query_yaml['Query']
                elif 'SnowflakeQuery' in query_yaml:
                    sql = query_yaml['SnowflakeQuery']
                return extract_logtypes_from_sql(sql, logtype_lookup)

    if 'Query' in yaml:
        return extract_logtypes_from_sql(yaml['Query'], logtype_lookup)
    if 'SnowflakeQuery' in yaml:
        return extract_logtypes_from_sql(yaml['SnowflakeQuery'], logtype_lookup)
    if yaml['AnalysisType'] == 'correlation_rule' and 'Detection' in yaml:
        log_types = []
        for detection in yaml['Detection']:
            if 'Sequence' in detection:
                for seq in detection['Sequence']:
                    if 'RuleID' not in seq:
                        continue
                    rule_yaml = query_lookup[seq['RuleID']]
                    extracted_log_types = extract_log_types_from_yaml(rule_yaml, query_lookup, logtype_lookup)
                    if extracted_log_types is None:
                        print('*** ERROR ***')
                        print(repr(rule_yaml))

                    for log_type in extracted_log_types:
                        if log_type not in log_types:
                            log_types.append(log_type)
            if 'Group' in detection:
                for group in detection['Group']:
                    if 'RuleID' not in group:
                        continue
                    rule_yaml = query_lookup[group['RuleID']]
                    extracted_log_types = extract_log_types_from_yaml(rule_yaml, query_lookup, logtype_lookup)
                    if extracted_log_types is None:
                        print('*** ERROR ***')
                        print(repr(rule_yaml))

                    for log_type in extracted_log_types:
                        if log_type not in log_types:
                            log_types.append(log_type)
        return log_types


# We use this to prefer showing the Scheduled Rules over their associated Query when they share the same name
def entry_scoring(entry):
    score = 0
    if entry['AnalysisType'] == 'Scheduled Query':
        score += 3
    if entry['AnalysisType'] == 'Scheduled Rule':
        score += 2
    if entry['AnalysisType'] == 'Rule':
        score += 1
    return score

def group_by(iterable, key=None):
    # Uses itertools.groupby to produce a dictionary where each key is the grouping defined by the key function
    if key is None:
        key = lambda x: x
    result = {}
    groups = itertools.groupby(iterable, key=key)
    for k, g in groups:
        result[k] = list(g)
    return result


def save_website_json(detections, query_lookup, logtype_lookup, json_path):
    json_export = []
    detection_types = collections.Counter()

    for d in detections.values():
        json_slice = {key: d[key] for key in
                      d.keys() & {'DisplayName', 'LogTypes', 'Description', 'AnalysisType', 'YAMLPath'}}
        # Clean up analysis type e.g. rule -> Rule and scheduled_rule -> Scheduled Rule
        json_slice['AnalysisType'] = ' '.join([x.capitalize() for x in json_slice['AnalysisType'].split('_')])
        if 'LogTypes' not in d or len(d['LogTypes']) == 0:
            json_slice['LogTypes'] = extract_log_types_from_yaml(d, query_lookup, logtype_lookup)

        detection_types[json_slice['AnalysisType']] += 1
        if 'LogTypes' in json_slice:
            json_slice['LogTypes'].sort()
        json_export.append(json_slice)
    name_map = {}
    for x in json_export:
        name = x['DisplayName'].lower()
        if name not in name_map:
            name_map[name] = []
        name_map[name].append(x)
    json_export = []
    for name in name_map:
        name_map[name] = list(sorted(name_map[name], key=entry_scoring, reverse=True))
        json_export.append(name_map[name][0])

    json_export = list(sorted(json_export, key=lambda x: x['DisplayName'].lower()))
    print("Writing detections-web-export.json...")
    with open(json_path, 'w') as fp:
        json.dump(json_export, fp, sort_keys=True)
    print(f"Total: {sum(detection_types.values())}")

# Splits the first part of a log type off to form a heading
def logtype_to_pretty(log_type):
    log_type_split = log_type.split('.')
    aliases = {
        'Amazon.EKS': 'AWS EKS',
        'Gravitational.Teleport': 'Teleport',
        'GSuite': 'Google Workspace'
    }
    if log_type_split[0] == 'AWS':
        return f"{log_type_split[0]} {log_type_split[1]}"
    for alias, pretty in aliases.items():
        if alias in log_type:
            return pretty
    return log_type_split[0]


def write_alpha_index(detections, query_lookup, logtype_lookup, root_dir):
    # Map each detection to each of its log types, then write an alphabetic index of all log types
    logtype_mapping = {}
    valid_detections = []
    for d in detections.values():
        json_slice = {key: d[key] for key in
                      d.keys() & {'DisplayName', 'LogTypes', 'Description', 'AnalysisType', 'YAMLPath'}}

        if 'LogTypes' not in d or len(d['LogTypes']) == 0:
            json_slice['LogTypes'] = extract_log_types_from_yaml(d, query_lookup, logtype_lookup)
        valid_detections.append(json_slice)

    # Dedupe detections by DisplayName
    name_map = group_by(valid_detections, key=lambda x: x['DisplayName'].lower())
    standard_rules = []
    json_export = []
    for name in name_map:
        name_map[name] = list(sorted(name_map[name], key=entry_scoring, reverse=True))
        winner = name_map[name][0]

        headings = set(map(logtype_to_pretty, winner['LogTypes']))
        for log_type in headings:
            if log_type not in logtype_mapping:
                logtype_mapping[log_type] = []
            logtype_mapping[log_type].append(winner)
        if 'standard_rules' in winner['YAMLPath']:
            winner['Headings'] = headings
            standard_rules.append(winner)
        json_export.append(name_map[name][0])

    output = "# Alpha Index\n\n"
    letter_buckets = group_by(sorted(logtype_mapping.keys()), key=lambda x: x[0].upper())
    letters = sorted(letter_buckets.keys())
    for letter in letters:
        output += f"- [{letter}](#{letter})\n"

    for letter in letters:
        output += f"# {letter}\n\n"
        for log_type in sorted(letter_buckets[letter]):
            output += f"- [{log_type}](#{log_type.replace('.', '').replace(' ', '-').lower()})\n"
        output += "\n\n"
        for log_type in sorted(letter_buckets[letter]):
            output += f"## {log_type}\n\n"
            logtype_mapping[log_type] = sorted(logtype_mapping[log_type], key=lambda x: x['DisplayName'].lower())
            for detection in logtype_mapping[log_type]:
                output += f"- [{detection['DisplayName']}](../{detection['YAMLPath']})\n"
                if len(detection['Description']) > 3:
                    output += f"  - {detection['Description']}\n"
            output += "\n\n"

    with open(root_dir / 'indexes' / 'alpha-index.md', 'w') as fp:
        fp.write(output)

    index_files = {
        'aws': ['AWS'],
        'gcp': ['GCP'],
        'github': ['GitHub'],
        'gworkspace': ['Google Workspace'],
        'okta': ['Okta'],
        'onelogin': ['OneLogin'],
        'onepass': ['OnePassword'],
        'osquery': ['Osquery'],
        'saas': ['Box', 'Dropbox', 'Google Workspace', 'Microsoft 365', 'Okta', 'OneLogin', 'Salesforce', 'Slack', 'Teleport', 'Zoom', 'Zendesk'],
        'snowflake': ['Snowflake'],
    }
    all_log_types = sorted(logtype_mapping.keys())
    for index_file, log_types in index_files.items():
        output = ""

        for log_type in all_log_types:
            if not any([log_type.startswith(prefix) for prefix in log_types]):
                continue
            output += f"## {log_type}\n\n"
            logtype_mapping[log_type] = sorted(logtype_mapping[log_type], key=lambda x: x['DisplayName'].lower())
            for detection in logtype_mapping[log_type]:
                output += f"- [{detection['DisplayName']}](../{detection['YAMLPath']})\n"
                if len(detection['Description']) > 3:
                    output += f"  - {detection['Description']}\n"
            output += "\n\n"
        with open(root_dir / 'indexes' / f'{index_file}.md', 'w') as fp:
            fp.write(output)

    # Write out the standard rules, this is a separate case because we list each log type below the detection
    output = """## Panther Standard Detections

### Supported Log Types are listed below each detection\n\n"""
    standard_rules = sorted(standard_rules, key=lambda x: x['DisplayName'].lower())
    for detection in standard_rules:
        output += f"[{detection['DisplayName']}](../{detection['YAMLPath']})  \n"
        if detection['Description']:
            output += f"{detection['Description']}\n"

        for heading in detection['Headings']:
            output += f"  - {heading}\n"
        output += "\n\n"
    with open(root_dir / 'indexes' / 'standard.md', 'w') as fp:
        fp.write(output)

if __name__ == '__main__':
    # Assume that this script is in the .scripts directory and we want to run on the root of the repo
    root_dir = pathlib.Path(__file__).parent.parent.resolve()
    generate_indexes(root_dir)
