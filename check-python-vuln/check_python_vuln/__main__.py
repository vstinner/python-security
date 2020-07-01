import os
import subprocess
import sys

from .vulntools import TestResult, TestResultError, ERROR, VULNERABLE


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
        self.results = []

    def search_scripts(self):
        module_path = os.path.dirname(__file__)

        for filename in os.listdir(module_path):
            if not filename.endswith(".py"):
                continue
            if filename[:-3] == "vulntools":
                continue
            if filename.startswith("_"):
                # ignore __init__.py and __main__.py
                continue
            filename = os.path.join(module_path, filename)
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
            err_msg = ('%s failed with exit code %s: %s'
                       % (os.path.basename(script),
                          exitcode, stderr))
            result = TestResultError(script, err_msg)
        else:
            result = TestResult.from_json(script, stdout)
        print("* %s" % result)
        return result

    def run_scripts(self):
        python = ' '.join(self.python)
        print("Result for %s (%s):" % (python, self.python_version))
        for script in self.scripts:
            result = self.run_script(script)
            self.results.append(result)
        print("")

    def display_results(self):
        any_error = any(result.status == ERROR for result in self.results)
        vuln = sum(result.status == VULNERABLE for result in self.results)

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


def main():
    Application().main()


if __name__ == "__main__":
    main()
