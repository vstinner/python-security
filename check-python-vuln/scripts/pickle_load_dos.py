import os.path
import pickle
import sys
import vulntools

vulntools.limit_resources()
filename = vulntools.data_file("pickle_load_dos.pickle")
try:
    with open(filename, "rb") as fp:
        pickle.load(fp)
except ValueError as exc:
    if "unsupported pickle protocol: 4" in str(exc):
        vulntools.exit_skip(str(exc))
    else:
        vulntools.exit_error(str(exc))
except MemoryError as exc:
    vulntools.exit_vulnerable(repr(exc))

vulntools.exit_fixed()
