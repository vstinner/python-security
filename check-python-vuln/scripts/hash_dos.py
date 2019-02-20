import sys
import subprocess
import vulntools


SET_SIZE = 128
NVALUE = 16


vulntools.prepare_process()

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
        vulntools.exit_error("python failed with exitcode %s"
                             % proc.returncode)
    results.append(stdout.rstrip())

unique = len(set(results))
if unique == NVALUE:
    vulntools.exit_fixed()
else:
    vulntools.exit_vulnerable("set is not randomized (%s unique repr)" % unique)
