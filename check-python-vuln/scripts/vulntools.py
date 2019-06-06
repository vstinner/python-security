from __future__ import print_function

import json
import math
import os.path
import signal
import sys
try:
    import resource
except ImportError:
    resource = None


URL_FORMAT = 'https://python-security.readthedocs.io/vuln/%s.html'
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
MEMORY_LIMIT = 2 * 1024 ** 3   # 2 GiB
TIMEOUT = 30.0   # seconds


class Status:
    def __init__(self, value, message, exitcode):
        self.value = value
        self.message = message
        self.exitcode = exitcode

    def __eq__(self, other):
        if self is other:
            return True
        return (self.value == other.value)

    def __str__(self):
        return self.value


FIXED = Status("FIXED", "vulnerability fixed", 100)
VULNERABLE = Status("VULNERABLE", "Vulnerable!", 101)
SKIP = Status("SKIP", "script skipped", 102)
ERROR = Status("ERROR", "script failed", 103)

_ALL_STATUS = (FIXED, VULNERABLE, SKIP, ERROR)

# used by deserialize_status()
_STATUS_FROM_VALUE = dict((status.value, status) for status in _ALL_STATUS)


def set_memory_limit(size=None):
    if not size:
        size = MEMORY_LIMIT
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_AS, (size, size))


class Timeout(BaseException):
    pass


def set_time_limit(timeout=None):
    if timeout is None:
        timeout = TIMEOUT

    def signal_handler(signum, frame):
        raise Timeout("timeout (%.1f sec)" % timeout)

    signal.signal(signal.SIGALRM, signal_handler)
    timeout_secs = int(math.ceil(timeout))
    signal.alarm(timeout_secs)


class TestResult:
    def __init__(self, script, status):
        self.script = script
        self.status = status

    @staticmethod
    def from_json(script, stdout):
        try:
            result_dict = json.loads(stdout)
        except ValueError as exc:
            return TestResultError(script, "json error: %s" % exc)

        status = result_dict.pop('status')
        status = _STATUS_FROM_VALUE[status]

        result = TestResult(script, status)
        for name, value in result_dict.items():
            setattr(result, name, value)
        return result

    def __str__(self):
        text = '%s: %s' % (self.name, self.status)
        if self.status != FIXED and hasattr(self, 'message'):
            text = '%s (%s)' % (text, self.message)
        return text


class TestResultError(TestResult):
    def __init__(self, script, error_message):
        TestResult.__init__(self, script, ERROR)
        self.error_message = error_message

    def __str__(self):
        return "%s: %s" % (os.path.basename(self.script), self.error_message)


class Test:
    NAME = None
    SLUG = None

    def __init__(self):
        self.result = {}
        self.json_mode = False

        if not self.NAME:
            raise ValueError("NAME is not set")
        self.result['name'] = self.NAME

        if not self.SLUG:
            raise ValueError("SLUG is not set")
        slug = self.SLUG

        url = URL_FORMAT % slug
        self.result['url'] = url

    @staticmethod
    def data_file(filename):
        return os.path.join(DATA_DIR, filename)

    def _exit(self, status, message=None):
        self.result['status'] = status.value
        if message is not None:
            self.result['message'] = message

        if self.json_mode:
            json.dump(self.result, sys.stdout)
            sys.stdout.write("\n")
            exitcode = 0
        else:
            if message:
                print(message)
            else:
                print(status.message)
            exitcode = status.exitcode

        sys.stdout.flush()
        sys.exit(exitcode)

    def exit_fixed(self, msg=None):
        self._exit(FIXED, msg)

    def exit_vulnerable(self, msg=None):
        self._exit(VULNERABLE, msg)

    def exit_error(self, msg):
        self._exit(ERROR, msg)

    def exit_skip(self, msg=None):
        self._exit(SKIP, msg)

    @staticmethod
    def _prepare_process():
        if resource is not None:
            # Disable coredump creation
            old_value = resource.getrlimit(resource.RLIMIT_CORE)
            resource.setrlimit(resource.RLIMIT_CORE, (0, old_value[1]))

        set_memory_limit()
        set_time_limit()

    def main(self):
        self._prepare_process()

        if sys.argv[1:] == ["--json"]:
            self.json_mode = True
        elif sys.argv[1:]:
            sys.stderr.write("Usage: %s %s [--json]\n"
                             % (sys.executable, sys.argv[0]))
            sys.stderr.flush()
            sys.exit(1)

        try:
            self.run()
        except Timeout as exc:
            self.exit_error(str(exc))

    def run(self):
        raise NotImplementedError
