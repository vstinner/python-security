#!/usr/bin/env python3
"""
Fake setup.py only used by .readthedocs.yaml to run the render_doc.py script to
build the documentation.
"""
import os
import sys

script = 'render_doc.py'
# render_doc.py
print("Run %s" % script)
sys.stdout.flush()
args = [sys.executable, script]
os.execv(args[0], args)
