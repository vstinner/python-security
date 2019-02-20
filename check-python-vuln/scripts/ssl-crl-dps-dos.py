import os.path
import sys
from vulntools import exit_error, exit_fixed
try:
    import _ssl
except ImportError as exc:
    exit_error("missing _ssl module: %s" % exc)

filename = os.path.join("data", "CVE-2019-5010.pem")
_ssl._test_decode_cert(filename)
exit_fixed()
