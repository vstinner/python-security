import sys

EXITCODE_FIXED = 100
EXITCODE_VULNERABLE = 101
EXITCODE_ERROR = 102

def exit_error(msg):
    print("CHECK FAILED: %s" % msg)
    sys.stdout.flush()
    sys.exit(EXITCODE_ERROR)

def exit_vulnerable():
    print("VULNERABLE!")
    sys.exit(EXITCODE_VULNERABLE)

def exit_fixed():
    print("vulnerability fixed")
    sys.exit(EXITCODE_FIXED)
