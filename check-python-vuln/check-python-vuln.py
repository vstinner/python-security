#!/usr/bin/env python3
import os
import subprocess
import sys
import textwrap

SCRIPTS_PATH = os.path.join(os.path.dirname(__file__), 'scripts')
sys.path.append(SCRIPTS_PATH)
import vulntools
from vulntools import TestResult, ERROR, VULNERABLE




class CommandResult:
    def __init__(self, command, exitcode, stdout, stderr):
        self.command = command
        self.exitcode = exitcode
        self.stdout = stdout
        self.stderr = stderr


class Application:
    def __init__(self):
        self.verbose = True
        self.debug = False
        self.python = [sys.executable]
        self.python_version = '%s.%s.%s' % tuple(sys.version_info[:3])
        root_dir = os.getcwd()
        self.data_dir = os.path.join(root_dir, 'data')
        self.scripts = []
        self.test_results = []

    def search_scripts(self):
        vulntools_filename = os.path.basename(vulntools.__file__)

        for filename in os.listdir(SCRIPTS_PATH):
            if not filename.endswith(".py"):
                continue
            if filename == vulntools_filename:
                continue
            filename = os.path.join(SCRIPTS_PATH, filename)
            if not os.path.isfile(filename):
                continue
            self.scripts.append(filename)

    def run_script(self, script):
        command = tuple(self.python + [os.path.basename(script), '--json'])
        if self.debug:
            cmd_text = ' '.join(command)
            print("+ %s" % cmd_text)
        proc = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                cwd=os.path.dirname(script))
        stdout, stderr = proc.communicate()

        exitcode = proc.returncode
        if exitcode:
            test_result = TestResult.deserialize_error(exitcode, stdout, stderr)
        else:
            test_result = TestResult.deserialize_result(stdout)
        test_result.script = script
        print("* %s" % test_result)
        return test_result

    def run_scripts(self):
        python = ' '.join(self.python)
        print("Result for %s (%s):" % (python, self.python_version))
        for script in self.scripts:
            test_result = self.run_script(script)
            self.test_results.append(test_result)
        print("")

    def display_results(self):
        any_error = any(test_result.result == ERROR
                        for test_result in self.test_results)
        vuln = sum(test_result.result == VULNERABLE
                   for test_result in self.test_results)

        fixed = True
        if any_error:
            print("CHECK ERROR :-(")
            fixed = False

        if vuln:
            print("Your Python %s has %s KNOWN VULNERABILIT%s!!!"
                  % (self.python_version, vuln, 'IES' if vuln != 1 else 'Y'))
            fixed = False
        if fixed:
            print("All tested vulnerabilities are fixed in your Python %s :-)"
                  % self.python_version)
        print("Tested executable: %s" % sys.executable)

    def main(self):
        self.search_scripts()
        self.run_scripts()
        self.display_results()


if __name__ == "__main__":
    Application().main()
