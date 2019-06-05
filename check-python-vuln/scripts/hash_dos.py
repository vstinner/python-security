import sys
import subprocess
from vulntools import Test


SET_SIZE = 128
NVALUE = 16


class Check(Test):
    NAME = "Hash DoS (CVE-2012-1150)"
    SLUG = "hash-dos"

    def run(self):
        code = 'print(repr(set(str(i) for i in range(%s))))' % SET_SIZE
        cmd = [sys.executable]
        if sys.version_info < (3,):
            cmd.append('-R')
        cmd.extend(('-c', code))

        results = []
        for _ in range(NVALUE):
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            stdout = proc.communicate()[0]
            if proc.returncode:
                self.exit_error("python failed with exitcode %s"
                                % proc.returncode)
            results.append(stdout.rstrip())

        unique = len(set(results))
        if unique == NVALUE:
            self.exit_fixed()
        else:
            self.exit_vulnerable("set is not randomized (%s unique repr)"
                                 % unique)


if __name__ == "__main__":
    Check().main()
