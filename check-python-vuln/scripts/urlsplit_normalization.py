try:
    import urllib.parse as urllib_parse
except ImportError:
    import urlparse as urllib_parse
import vulntools


def func():
    vulntools.exit_vulnerable()


vulntools.prepare_process()
for ch in (
    # Unicode characters converted to '/:#?@' by NFKC normalization.
    # List generated using Python 3.7: Unicode 11.0.
    # The list doesn't have the be complete to check if the Python is fixed.
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
):
    url = u'http://netloc{}false.netloc/path'.format(ch)
    try:
        urllib_parse.urlsplit(url)
    except ValueError:
        vulntools.exit_fixed()
    else:
        break

vulntools.exit_vulnerable()
