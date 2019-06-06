import sys
from vulntools import Test
try:
    import urllib.parse as urllib_parse
except ImportError:
    import urlparse as urllib_parse


try:
    ascii
except NameError:
    ascii = repr


# Unicode characters converted to '/:#?@' by NFKC normalization.
# List generated using Python 3.7: Unicode 11.0.
# The list doesn't have the be complete to check if the Python is fixed.
DENORM_CHARS = (
    u'\u2047',
    u'\u2048',
    u'\u2049',
    u'\u2100',
    u'\u2101',
    u'\u2105',
    u'\u2106',
    u'\u2a74',
    u'\ufe13',
    u'\ufe16',
    u'\ufe55',
    u'\ufe56',
    u'\ufe5f',
    u'\ufe6b',
    u'\uff03',
    u'\uff0f',
    u'\uff1a',
    u'\uff1f',
    u'\uff20',
)


def create_urls():
    for scheme in [u"http", u"https", u"ftp"]:
        for netloc in [u"netloc{0}false.netloc", u"n{0}user@netloc"]:
            for ch in DENORM_CHARS:
                url = u"{0}://{1}/path".format(scheme, netloc.format(ch))
                yield url


class Check(Test):
    NAME = "urlsplit does not handle NFKC normalization (CVE-2019-9636)"
    SLUG = "urlsplit-nfkc-normalization"

    def run(self):
        for url in create_urls():
            try:
                urllib_parse.urlsplit(url)
            except ValueError:
                sys.stderr.write("urlsplit(%s) raised ValueError\n"
                                 % ascii(url))
                # vulnerability fixed
                pass
            else:
                sys.stderr.write("urlsplit(%s) succeed but must raises "
                                 "ValueError: vulnerable!\n"
                                 % ascii(url))
                # vulnerable!
                self.exit_vulnerable()

        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
