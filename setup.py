#!/usr/bin/env python3
import os, subprocess, sys
script = 'render_doc.py'
# render_doc.py
print("Run %s" % script)
args = [sys.executable, script]
os.execv(args[0], args)
