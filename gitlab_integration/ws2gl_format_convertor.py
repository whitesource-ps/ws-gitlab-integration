#!/usr/bin/python3
import json
import os
from ws_sdk import WS, ws_constants, ws_utilities
import logging
import sys

SCHEMA_VER = "2.1"
DEPENDENCY = "dependency"
LICENSE = "license"
VUL_DB_URL = "https://www.whitesourcesoftware.com/vulnerability-database"

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='WS to GitLab convertor')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-k', '--token', help="WS Token", dest='ws_token', required=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default="saas")
    parser.add_argument('-t', '--conversionType', help="Conversion Type", choices=[LICENSE, DEPENDENCY], dest='conv_type', required=True)
    parser.add_argument('-o', '--outputDir', help="Output Dir", dest='output_dir', default=".")

    return parser.parse_args()


def validate_json(json_to_validate: dict):
    from jsonschema import validate, exceptions as json_exceptions


    if args.conv_type == LICENSE:
        f_name = "json_schemas/v2.1.json"
    elif args.conv_type == DEPENDENCY:
        f_name = "json_schemas/dependency-scanning-report-format.json"

    with open(f_name, 'r') as f:
        json_schema = f.read()

    json_schema_dict = json.loads(json_schema)
    try:
        validate(instance=json_to_validate, schema=json_schema_dict)
    except json_exceptions.SchemaError or json_exceptions.ValidationError:
        logging.exception("Validating failed JSON with schema")
        return False
    return True


def convert_license(conn):
    def get_lib_locations(library_location, library):
        locations = library_location.get('locations')
        if len(locations):
            if len(locations) > 1:
                logging.warning(f"Found {len(library_location['locations'])} locations for lib {library['name']}. Using the first one")
            loc_name = locations[0].get('path')
        else:
            logging.error(f"No locations found for lib {library['name']} ")
            loc_name = None

        return loc_name

    licenses = {}
    dependencies = []
    libs = conn.get_licenses(token=args.ws_token, full_spdx=True)
    libs_loc = ws_utilities.convert_dict_list_to_dict(conn.get_library_location(token=args.ws_token), 'keyUuid')

    for lib in libs:
        lib_loc = libs_loc[lib['keyUuid']]
        lics_lib = lib['licenses']
        curr_licenses = []
        for lic in lics_lib:
            if lic.get('spdx_license_dict'):
                gl_lic = {'id': lic['spdx_license_dict']['licenseId'],
                          'name': lic['spdx_license_dict']['name'],
                          'url': lic['url']}
                licenses[gl_lic['id']] = gl_lic
                curr_licenses.append(lic['spdx_license_dict']['licenseId'])
            else:
                logging.warning(f"SPDX data is missing on library {lib['name']} - license: {lic['name']}")

        dependencies.append({'name': lib['name'],
                             'version': lib['version'],
                             'package_manager': lib['type'],                # TODO: MAKE THIS MORE ACCURATE
                             'path': get_lib_locations(lib_loc, lib),
                             'licenses': curr_licenses})

    return {'version': SCHEMA_VER,
            'licenses': list(licenses.values()),
            'dependencies': dependencies}


def convert_dependency(conn):
    def convert_to_gl_vul(vulnerability, inventory):
        def get_solution():
            if vulnerability.get('topFix'):
                ret_fix = vulnerability['topFix']['fixResolution']
            else:
                ret_fix = "Fix unknown"
                logging.info(f"No fix found for {vulnerability['name']}")

            return ret_fix

        name = f"{vulnerability['name']}:{inventory['artifactId']}:{inventory['version']}"
        url = f"{VUL_DB_URL}/{vulnerability['name']}"
        gl_vul = {"category": "dependency_scanning",
                  "name": name,
                  "message": f"{vulnerability['name']} in {inventory['name']} - Detected by WhiteSource",
                  "description": vulnerability['description'],
                  "cve": vulnerability['name'],
                  "severity": vulnerability['severity'].capitalize(),
                  "confidence": "Confirmed",
                  "solution": get_solution(),
                  "scanner": {"id": "whitesource", "name": "WhiteSource"},
                  "location": {"file": inventory['name'],
                               "dependency": {"version": inventory['version'],
                                              "package": {"name": inventory['artifactId']}}},
                  "identifiers": [{"type": "whitesource",
                                   "name": name,
                                   "value": name,
                                   "url": url}],
                  "links": [{"url": url}]}

        return gl_vul

    vulnerabilities = conn.get_vulnerability(token=args.ws_token)
    inventory_list = ws_utilities.convert_dict_list_to_dict(conn.get_inventory(token=args.ws_token), 'keyUuid')

    gl_vuls = []
    for vul in vulnerabilities:
        lib_uuid = vul['library']['keyUuid']
        gl_vul = convert_to_gl_vul(vul, inventory_list[lib_uuid])
        gl_vuls.append(gl_vul)

    return {'version': SCHEMA_VER,
            'vulnerabilities': gl_vuls,
            'remediations': ""}


if __name__ == '__main__':
    args = parse_args()
    ws_conn = WS(url=args.ws_url, user_key=args.ws_user_key, token=args.ws_token, token_type=ws_constants.PROJECT)

    logging.info(f"Generating {args.conv_type} report")
    if args.conv_type == LICENSE:
        ret = convert_license(ws_conn)
        filename = "gl-license-scanning-report.json"
    elif args.conv_type == DEPENDENCY:
        ret = convert_dependency(ws_conn)
        filename = "gl-dependency-scanning-report.json"

    if os.environ.get("DEV_MODE"):
        validate_json(ret)

    full_path = os.path.join(args.output_dir, filename)
    logging.debug(f"Saving file to: {full_path}")
    with open(full_path, 'w') as fp:
        fp.write(json.dumps(ret))
