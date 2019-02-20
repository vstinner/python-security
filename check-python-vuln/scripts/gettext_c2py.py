import gettext
from vulntools import exit_vulnerable, exit_error, exit_fixed

def func():
    exit_vulnerable()

try:
    py = gettext.c2py("n()")
except ValueError:
    exit_fixed()
else:
    py(func)

exit_error()
