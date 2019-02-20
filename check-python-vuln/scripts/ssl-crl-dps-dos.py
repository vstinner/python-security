import os.path
import sys
import vulntools
try:
    import _ssl
except ImportError as exc:
    vulntools.exit_error("missing _ssl module: %s" % exc)

vulntools.prepare_process()
filename = vulntools.data_file("CVE-2019-5010.pem")
_ssl._test_decode_cert(filename)
vulntools.exit_fixed()
