from http.cookiejar import DefaultCookiePolicy
try:
    from urllib.request import Request
except ImportError:
    # Python 2
    from urllib2 import Request
import vulntools


vulntools.prepare_process()

policy = DefaultCookiePolicy()
req = Request('https://xxxfoo.co.jp/')
if policy.domain_return_ok('foo.co.jp', req):
    vulntools.exit_vulnerable()
else:
    vulntools.exit_fixed()
