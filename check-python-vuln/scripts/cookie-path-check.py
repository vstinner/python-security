try:
    from urllib.request import Request
    from http.cookiejar import DefaultCookiePolicy
except ImportError:
    # Python 2
    from urllib2 import Request
    from cookielib import DefaultCookiePolicy
import vulntools


vulntools.prepare_process()

policy = DefaultCookiePolicy()
req = Request('https://example.com/anybad')
if policy.path_return_ok('/any', req):
    vulntools.exit_vulnerable()
else:
    vulntools.exit_fixed()
