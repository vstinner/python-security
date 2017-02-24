#!/bin/bash
set -e -x
python3 -m venv --without-pip venv
wget https://bootstrap.pypa.io/get-pip.py
venv/bin/python get-pip.py
venv/bin/python -m pip install -U PyYAML
