#!/usr/bin/python3
import json
import os
from typing import List

from ws_sdk import WS, ws_constants, ws_utilities
import logging
import sys

SCANNER_ID = "ws-gl-int"
LICENSE_SCHEMA_V = "2.1"
DEPENDENCY_SCHEMA_V = "14.0.2"
DEPENDENCY = "dependency"
DEPENDENCY_ALERTS_BASED = "dependency_alert_based"
LICENSE = "license"
VUL_DB_URL = "https://www.whitesourcesoftware.com/vulnerability-database"
IS_DEBUG = True if os.environ.get("DEBUG") else False
CONCAT_SCOPE_NAME = False
LOG_LEVEL = logging.DEBUG if IS_DEBUG else logging.INFO

logging.basicConfig(level=LOG_LEVEL, stream=sys.stdout)
args = None


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='WS to GitLab convertor')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-k', '--token', help="WS Project Token", dest='ws_token', required=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default="saas")
    parser.add_argument('-t', '--conversionType', help="Conversion Type", choices=[LICENSE, DEPENDENCY, DEPENDENCY_ALERTS_BASED], dest='conv_type', required=True)
    parser.add_argument('-o', '--outputDir', help="Output Dir", dest='output_dir', default=".")

    return parser.parse_args()


def validate_json(json_to_validate: dict) -> bool:
    from jsonschema import validate, exceptions as json_exceptions
    import requests
    import json

    if args.conv_type == LICENSE:
        url = 'https://gitlab.com/gitlab-org/security-products/analyzers/license-finder/-/raw/main/spec/fixtures/schema/v2.1.json'
    elif args.conv_type.startswith(DEPENDENCY):
        url = 'https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/dependency-scanning-report-format.json'

    resp = requests.get(url=url)
    json_schema = json.loads(resp.text)

    try:
        validate(instance=json_to_validate, schema=json_schema)
    except json_exceptions.SchemaError or json_exceptions.ValidationError:
        logging.exception("Validating failed JSON with schema")
        return False
    return True


def convert_license(conn) -> dict:
    def get_lib_locations(library_location, library) -> str:
        locations = library_location.get('locations')
        if len(locations):
            if len(locations) > 1:
                logging.warning(f"Found {len(library_location['locations'])} locations for lib {library['name']}. Using the first one")
            loc_name = locations[0].get('path')
        else:
            logging.warning(f"No locations found for lib {library['name']} ")
            loc_name = None

        return loc_name

    def get_package_manager(language) -> str:
        pkg_man = ws_utilities.get_package_managers_by_language(language)
        return "unknown" if not pkg_man else pkg_man[0]

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
                             'version': lib.get('version'),     # TODO: ADD METHOD in ws_utilities to break LIB-1.2.3.SFX to GAV
                             'package_manager': get_package_manager(lib['type']).capitalize(),
                             'path': get_lib_locations(lib_loc, lib),
                             'licenses': sorted(curr_licenses)})

    return {'version': LICENSE_SCHEMA_V,
            'licenses': sorted(list(licenses.values()), key=lambda k: k['id']),
            'dependencies': dependencies}


def convert_dependency(conn) -> dict:
    def convert_to_gl_vul(vulnerability, inventory) -> dict:
        def get_solution() -> str:
            top_fix = vulnerability.get('topFix')
            if top_fix:
                ret_fix = vulnerability.get('fixResolutionText', top_fix['fixResolution'])
            else:
                ret_fix = "Fix unknown"
                logging.info(f"No fix found for {vulnerability['name']}")
            logging.debug(f"Found fix to vulnerability: {vulnerability['name']} Fix: {ret_fix}")

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
                  "scanner": {"id": SCANNER_ID, "name": "WhiteSource"},
                  "location": {"file": inventory['name'],
                               "dependency": {"version": inventory['version'],
                                              "package": {"name": inventory['artifactId']}}},
                  "identifiers": [{"type": "whitesource",
                                   "name": name,
                                   "value": name,
                                   "url": url}],
                  "links": [{"url": url}]}

        return gl_vul

    vulnerabilities = []
    if args.conv_type == DEPENDENCY:
        vulnerabilities = conn.get_vulnerability(token=args.ws_token)
    elif args.conv_type == DEPENDENCY_ALERTS_BASED:
        security_alerts = conn.get_alerts(alert_type=ws_constants.AlertTypes.SECURITY_VULNERABILITY)

        for sec_alert in security_alerts:
            vul = sec_alert['vulnerability']
            vul['library'] = sec_alert['library']
            vulnerabilities.append(vul)

    inventory_dict = ws_utilities.convert_dict_list_to_dict(conn.get_inventory(token=args.ws_token), 'keyUuid')

    gl_vuls = []
    for vul in vulnerabilities:
        lib_uuid = vul['library']['keyUuid']
        gl_vul = convert_to_gl_vul(vul, inventory_dict[lib_uuid])
        gl_vuls.append(gl_vul)

    return {'version': DEPENDENCY_SCHEMA_V,
            'vulnerabilities': gl_vuls,
            'remediations': [],
            'dependency_files': []}


def main() -> List[list, str]:
    global args
    args = parse_args()
    ws_conn = WS(url=args.ws_url, user_key=args.ws_user_key, token=args.ws_token, token_type=ws_constants.PROJECT)

    logging.info(f"Generating {args.conv_type} report")
    if args.conv_type == LICENSE:
        ret = convert_license(ws_conn)
        filename = "gl-license-scanning-report.json"
    elif args.conv_type.startswith(DEPENDENCY):
        ret = convert_dependency(ws_conn)
        filename = "gl-dependency-scanning-report.json"

    if IS_DEBUG:
        validate_json(ret)

    if CONCAT_SCOPE_NAME:
        scope_name = ws_conn.get_scope_name_by_token(token=args.ws_token)

        for char in [':', '#', '*', '\\']:
            scope_name = scope_name.replace(char, '_')
        filename = f"{scope_name}-{filename}"

    full_path = os.path.join(args.output_dir, filename)
    logging.debug(f"Saving file to: {full_path}")
    with open(full_path, 'w') as fp:
        fp.write(json.dumps(ret))

    return ret, filename


if __name__ == '__main__':
    main()
    