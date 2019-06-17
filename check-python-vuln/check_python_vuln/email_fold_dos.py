from vulntools import Test, SHORT_TIMEOUT, wait_process
import subprocess
import sys

code = r"""
import email.policy
policy = email.policy.default.clone(max_line_length=20)
actual = policy.fold('Subject', '\u0105' * 12)
"""
TIMEOUT = SHORT_TIMEOUT


class Check(Test):
    NAME = "Email folding function Denial-of-Service"
    SLUG = "email-fold-dos"

    def run(self):
        args = [sys.executable, '-c', code]
        proc = subprocess.Popen(args)
        if not wait_process(proc, TIMEOUT):
            self.exit_vulnerable("Timeout after %.1f sec" % TIMEOUT)
        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
