#!/bin/bash
set -e -x
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt
