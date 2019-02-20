from __future__ import print_function

import os.path
import math
import sys
try:
    import resource
except ImportError:
    resource = None
import signal


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
MEMORY_LIMIT = 2 * 1024 ** 3   # 2 GiB
TIMEOUT = 30.0

EXITCODE_FIXED = 100
EXITCODE_VULNERABLE = 101
EXITCODE_SKIP = 102
EXITCODE_ERROR = 103


def data_file(filename):
    return os.path.join(DATA_DIR, filename)


def set_memory_limit(size=None):
    if not size:
        size = MEMORY_LIMIT
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_AS, (size, size))
    print("Memory limit set to %.1f GiB" % (size / (1024. ** 3)),
          file=sys.stderr)


def alarm_handler(timeout):
    exit_error("timeout (%.1f sec)" % TIMEOUT)


def set_time_limit(timeout=None):
    if timeout is None:
        timeout = TIMEOUT

    def signal_handler(signum, frame):
        alarm_handler(timeout)

    signal.signal(signal.SIGALRM, signal_handler)
    timeout_secs = int(math.ceil(timeout))
    signal.alarm(timeout_secs)


def limit_resources():
    set_memory_limit()
    set_time_limit()


def prepare_process():
    if resource is None:
        return

    # Disable coredump creation
    old_value = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, old_value[1]))

    limit_resources()


def exit_error(msg):
    print("CHECK FAILED: %s" % msg)
    sys.stdout.flush()
    sys.exit(EXITCODE_ERROR)


def exit_vulnerable(msg=None):
    text = "VULNERABLE!"
    if msg:
        text = "%s %s" % (text, msg)
    print(text)
    sys.exit(EXITCODE_VULNERABLE)


def exit_fixed():
    print("vulnerability fixed")
    sys.exit(EXITCODE_FIXED)


def exit_skip(msg):
    if msg:
        print("SKIP CHECK: %s" % msg)
    else:
        print("SKIP CHECK")
    sys.exit(EXITCODE_SKIP)
