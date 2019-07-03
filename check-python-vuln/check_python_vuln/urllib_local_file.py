from __future__ import print_function
try:
    from urllib import request as urllib_request
    from urllib.request import URLopener
except ImportError:
    # Python 2
    from urllib import URLopener
    import urllib2 as urllib_request
import sys
import warnings
from vulntools import Test


class Check(Test):
    NAME = "urllib module local_file:// scheme (CVE-2019-9948)"
    SLUG = "urllib-local-file-scheme"

    def check_func(self, func_name, func):
        for url in ('local_file://example', 'local-file://example'):
            print("Test %s(%r)" % (func_name, url), file=sys.stderr)
            try:
                func(url)
            except IOError:
                pass
            else:
                self.exit_vulnerable("%s(%r) didn't raise an exception"
                                     % (func_name, url))

    def run(self):
        # bpo-35907, CVE-2019-9948: urllib must reject local_file:// scheme
        class DummyURLopener(URLopener):
            def open_local_file(self, url):
                return url

        warnings.simplefilter('ignore', DeprecationWarning)
        self.check_func("urlopen", urllib_request.urlopen)
        self.check_func("URLopener().open", URLopener().open)
        self.check_func("URLopener().retrieve", URLopener().retrieve)
        self.check_func("DummyURLopener().open", DummyURLopener().open)
        self.check_func("DummyURLopener().retrieve", DummyURLopener().retrieve)
        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
