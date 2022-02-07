import json
import os
import unittest
from unittest import TestCase, mock
from unittest.mock import MagicMock
from ws_gitlab_integration import ws2gl_format_convertor

debug = mock.patch.dict(os.environ, {"DEBUG": 'True'})
debug.start()


class WsGitLabIntegrationTest(TestCase):
    user_key = os.environ['WS_USER_KEY']
    ws_token = os.environ['WS_SCOPE_PROJ']
    ws2gl_format_convertor.parse_args = MagicMock()
    ws2gl_format_convertor.parse_args.return_value.ws_user_key = user_key
    ws2gl_format_convertor.parse_args.return_value.ws_token = ws_token
    ws2gl_format_convertor.parse_args.return_value.ws_url = 'saas'
    ws2gl_format_convertor.parse_args.return_value.output_dir = '.'

    def setUp(self) -> None:
        self.maxDiff = 2147483648

    def test_dependency(self):
        ws2gl_format_convertor.parse_args.return_value.conv_type = ws2gl_format_convertor.DEPENDENCY
        ret = ws2gl_format_convertor.main()
        compared_json = get_compared_json(ret[1])

        self.assertDictEqual(ret[0], compared_json)

    def test_dependency_alerts(self):
        ws2gl_format_convertor.parse_args.return_value.conv_type = ws2gl_format_convertor.DEPENDENCY_ALERTS_BASED
        ret = ws2gl_format_convertor.main()
        compared_json = get_compared_json('gl-dependency-scanning-report-alert-based.json')

        self.assertDictEqual(ret[0], compared_json)

    def test_license(self):
        ws2gl_format_convertor.parse_args.return_value.conv_type = ws2gl_format_convertor.LICENSE
        ret = ws2gl_format_convertor.main()
        compared_json = get_compared_json(ret[1])

        self.assertDictEqual(ret[0], compared_json)


def get_compared_json(filename):
    path = f'samples/{filename}'
    with open(path, 'r') as fp:
        return json.loads(fp.read())


if __name__ == '__main__':
    unittest.main()
