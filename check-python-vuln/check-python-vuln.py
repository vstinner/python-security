#!/usr/bin/env python3
import os
import subprocess
import sys
import textwrap

scripts_path = os.path.join(os.path.dirname(__file__), 'scripts')
sys.path.append(scripts_path)
import vulntools


FMT_URL = 'https://python-security.readthedocs.io/vuln/%s.html'


FIXED = "fixed"
CHECK_ERROR = "CHECK_ERROR"
SKIP = "skipped"
VULNERABLE = "VULNERABLE"


class CommandResult:
    def __init__(self, command, exitcode, stdout, stderr):
        self.command = command
        self.exitcode = exitcode
        self.stdout = stdout
        self.stderr = stderr


class Checker:
    NAME = None
    SLUG = None

    def __init__(self, app):
        self.app = app
        self.result = CHECK_ERROR

    def data_file(self, filename):
        return os.path.join(self.app.data_dir, filename)

    def url(self):
        return FMT_URL % self.SLUG

    def run_python(self, *args, **kw):
        command = tuple(self.app.python + list(args))
        if self.app.debug:
            cmd_text = ' '.join(command)
            print("+ %s" % cmd_text)
        proc = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                **kw)
        stdout, stderr = proc.communicate()
        exitcode = proc.returncode
        self.cmd_result = CommandResult(command, exitcode, stdout, stderr)
        if self.app.debug:
            print("+ %s => exit code %s" % (cmd_text, exitcode))

        if exitcode == vulntools.EXITCODE_FIXED:
            self.result = FIXED
        elif exitcode == vulntools.EXITCODE_VULNERABLE:
            self.result = VULNERABLE
        elif exitcode == vulntools.EXITCODE_SKIP:
            self.result = SKIP
        elif exitcode < 0:
            # likely a crash
            self.result = VULNERABLE
        else:
            self.result = CHECK_ERROR

    def run_script(self, script):
        filename = os.path.join(scripts_path, script)
        if not os.path.exists(filename):
            raise Exception("%s doesn't exist" % filename)
        self.run_python(script, cwd=scripts_path)

    def run(self):
        self.run_script(self.SCRIPT)


class SslCrlDpsDos(Checker):
    NAME = "SSL CRL DPS DoS (CVE-2019-5010)"
    SLUG = "ssl-crl-dps-dos"
    SCRIPT = "ssl-crl-dps-dos.py"


class GettextC2P(Checker):
    NAME = "gettext.c2py (bpo-28563)"
    SLUG = "gettext-c2py"
    SCRIPT = "gettext_c2py.py"


class SslNulSubjectNames(Checker):
    NAME = "SLL NUL in subjectAltNames (CVE-2013-4238)"
    SLUG = "ssl-null-subjectaltnames"
    SCRIPT = "ssl_nul_in_subjectaltnames.py"


class HashDos(Checker):
    NAME = "Hash DoS (CVE-2012-1150)"
    SLUG = "hash-dos"
    SCRIPT = "hash_dos.py"


class UrlsplitNormalization(Checker):
    NAME = "urlsplit does not handle NFKC normalization (CVE-2019-9636)"
    SLUG = "urlsplit-nfkc-normalization"
    SCRIPT = "urlsplit_normalization.py"


CHECKERS = [SslCrlDpsDos, GettextC2P, SslNulSubjectNames, HashDos, UrlsplitNormalization]


class Application:
    def __init__(self):
        self.verbose = True
        self.debug = False
        self.python = [sys.executable]
        root_dir = os.getcwd()
        self.data_dir = os.path.join(root_dir, 'data')
        self.checkers = []

    def run_checkers(self):
        for checker_class in CHECKERS:
            checker = checker_class(self)
            if self.verbose:
                print("Check: %s" % checker.NAME)
            checker.run()
            self.checkers.append(checker)

        print("")

    def display_results(self):
        python = ' '.join(self.python)
        version = '%s.%s.%s' % tuple(sys.version_info[:3])
        print("Result for %s (%s):" % (python, version))
        vuln = 0
        for checker in self.checkers:
            result = checker.result
            if result == CHECK_ERROR:
                errmsg = checker.cmd_result.stdout.rstrip()
                if errmsg:
                    result = '%s (%s)' % (result, errmsg)
            print("* %s: %s" % (checker.NAME, result))
            if checker.result == VULNERABLE:
                vuln += 1
        print("")

        fixed = True
        if any(checker.result == CHECK_ERROR for checker in self.checkers):
            print("CHECK ERROR :-(")
            fixed = False
        if vuln:
            print("Your Python %s has %s KNOWN VULNERABILIT%s!!!"
                  % (version, vuln, 'IES' if vuln != 1 else 'Y'))
            fixed = False
        if fixed:
            print("All tested vulnerabilities are fixed in your Python %s :-)"
                  % version)
        print("Tested executable: %s" % sys.executable)

    def main(self):
        self.run_checkers()
        self.display_results()


if __name__ == "__main__":
    Application().main()
