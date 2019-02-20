import gettext
import vulntools


def func():
    vulntools.exit_vulnerable()


vulntools.prepare_process()
try:
    py = gettext.c2py("n()")
except ValueError:
    vulntools.exit_fixed()
else:
    py(func)

vulntools.exit_error()
