#!/bin/bash
set -e -x
python3 -m venv --without-pip venv
if [ ! -e get-pip.py ]; then
    wget https://bootstrap.pypa.io/get-pip.py
fi
venv/bin/python get-pip.py
venv/bin/python -m pip install -r requirements.txt
