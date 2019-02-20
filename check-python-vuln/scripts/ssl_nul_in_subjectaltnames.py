import os.path
import sys
import vulntools
try:
    import _ssl
except ImportError as exc:
    vulntools.exit_error("missing _ssl module: %s" % exc)

filename = vulntools.data_file("nullbytecert.pem")
_ssl._test_decode_cert(filename)
vulntools.exit_fixed()
