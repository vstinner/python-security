from http.cookiejar import DefaultCookiePolicy
try:
    from urllib.request import Request
except ImportError:
    # Python 2
    from urllib2 import Request
from vulntools import Test


class Check(Test):
    NAME = "Cookie domain check returns incorrect results"
    SLUG = "cookie-domain-check"

    def run(self):
        policy = DefaultCookiePolicy()
        req = Request('https://xxxfoo.co.jp/')
        if policy.domain_return_ok('foo.co.jp', req):
            self.exit_vulnerable()
        else:
            self.exit_fixed()


if __name__ == "__main__":
    Check().main()
