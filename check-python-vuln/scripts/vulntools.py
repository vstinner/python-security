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


FIXED = "FIXED"
VULNERABLE = "VULNERABLE"
SKIP = "SKIP"
ERROR = "ERROR"

# used by deserialize_result()
RESULTS = {
    FIXED: FIXED,
    VULNERABLE: VULNERABLE,
    SKIP: SKIP,
    ERROR: ERROR,
}

EXITCODES = {
    FIXED: 100,
    VULNERABLE: 101,
    SKIP: 102,
    ERROR: 103,
}


def set_memory_limit(size=None):
    if not size:
        size = MEMORY_LIMIT
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_AS, (size, size))
    print("Memory limit set to %.1f GiB" % (size / (1024. ** 3)),
          file=sys.stderr)


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
    def __init__(self):
        pass

    @staticmethod
    def deserialize_result(stdout):
        result_dict = json.loads(stdout)
        result = result_dict['result']
        result_dict['result'] = RESULTS[result]

        test_result = TestResult()
        for name, value in result_dict.items():
            setattr(test_result, name, value)
        return test_result

    @staticmethod
    def deserialize_error(exitcode, stdout, stderr):
        test_result = TestResult()
        test_result.result = ERROR
        test_result.exitcode = exitcode
        test_result.stdout = stdout
        test_result.stderr = stderr
        return test_result

    def __str__(self):
        if hasattr(self, 'exitcode'):
            return ('%s failed with exit code %s: %s'
                    % (os.path.basename(self.script),
                       self.exitcode, self.stderr))
        else:
            text = '%s: %s' % (self.name, self.result)
            if self.result != FIXED and hasattr(self, 'message'):
                text = '%s (%s)'%  (text, self.message)
            return text


class Test:
    NAME = None
    SLUG = None

    def __init__(self):
        self.test_result = {}
        self.json_mode = False

        if not self.NAME:
            raise ValueError("NAME is not set")
        self.test_result['name'] = self.NAME

        if not self.SLUG:
            raise ValueError("SLUG is not set")
        slug = self.SLUG

        url = URL_FORMAT % slug
        self.test_result['url'] = url

    @staticmethod
    def data_file(filename):
        return os.path.join(DATA_DIR, filename)

    def _exit(self, result, message=None):
        self.test_result['result'] = result
        if message is not None:
            self.test_result['message'] = message

        if self.json_mode:
            json.dump(self.test_result, sys.stdout)
            sys.stdout.write("\n")
            exitcode = 0
        else:
            print(message)
            exitcode = EXITCODES[result]

        sys.stdout.flush()
        sys.exit(exitcode)

    def exit_fixed(self):
        self._exit(FIXED, "vulnerability fixed")

    def exit_vulnerable(self, msg=None):
        self._exit(VULNERABLE, msg)

    def exit_error(self, msg):
        self._exit(ERROR, msg)

    def exit_skip(self, msg):
        if msg:
            msg = "SKIP CHECK: %s" % msg
        else:
            msg = "SKIP CHECK"
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
