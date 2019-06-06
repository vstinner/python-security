try:
    from urllib.request import Request
    from http.cookiejar import DefaultCookiePolicy
except ImportError:
    # Python 2
    from urllib2 import Request
    from cookielib import DefaultCookiePolicy
from vulntools import Test


class Check(Test):
    NAME = "Cookie path check returns incorrect results"
    SLUG = "cookie-path-check"

    def run(self):
        policy = DefaultCookiePolicy()
        req = Request('https://example.com/anybad')
        if policy.path_return_ok('/any', req):
            self.exit_vulnerable()
        else:
            self.exit_fixed()


if __name__ == "__main__":
    Check().main()
