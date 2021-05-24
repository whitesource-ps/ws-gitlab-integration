import json
import os

from ws_sdk import WS, ws_constants
import logging
import sys

SCHEMA_VER = "2.1"
SECURITY = "security"
LICENSE = "license"

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='WS to GitLab convertor')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-k', '--token', help="WS Token", dest='ws_token', required=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default="saas")
    parser.add_argument('-t', '--conversionType', help="Conversion Type", choices=[LICENSE, SECURITY], dest='conv_type', required=True)
    parser.add_argument('-o', '--outputDir', help="Output Dir", dest='output_dir', default=".")

    return parser.parse_args()


def convert_license(conn):
    licenses = {}
    dependencies = []
    libs = conn.get_licenses(full_spdx=True)
    for lib in libs:
        lics_lib = lib['licenses']
        curr_licenses = []
        for lic in lics_lib:
            if lic.get('spdx_license_dict'):
                gl_lic = {'id': lic['spdx_license_dict']['licenseId'],
                          'name': lic['spdx_license_dict']['name'],
                          'url': lic['spdx_license_dict']['detailsUrl']}
                licenses[gl_lic['id']] = gl_lic
                curr_licenses.append(lic['spdx_license_dict']['licenseId'])
            else:
                logging.warning(f"SPDX data is missing on library {lib['name']} - license: {lic['name']}")

        dependencies.append({'name': lib['name'],
                             'version': lib['version'],
                             'package_manager': lib['type'],                # TODO FIX THIS
                             'path': "PATH",                                # TODO FIX THIS
                             'licenses': curr_licenses})

    return {'version': SCHEMA_VER,
            'licenses': list(licenses.values()),
            'dependencies': dependencies}


def convert_security(conn):
    return {}


if __name__ == '__main__':
    args = parse_args()
    ws_conn = WS(url=args.ws_url, user_key=args.ws_user_key, token=args.ws_token, token_type=ws_constants.PROJECT)

    logging.info(f"Generating {args.conv_type} report")
    if args.conv_type == LICENSE:
        ret = convert_license(ws_conn)
        filename = "gitlab-license-model-test.json"
    elif args.conv_type == SECURITY:
        ret = convert_security(ws_conn)
        filename = "gitlab-security-violation-model-test.json"

    full_path = os.path.join(args.output_dir, filename)
    logging.debug(f"Saving file to: {full_path}")
    with open(full_path, 'w') as fp:
        fp.write(json.dumps(ret))
