Python Security documentation: http://python-security.readthedocs.io/

Input files:

* ``vulnerabilities.yml``: Python vulnerabilities 2007-2017, see the commented
  template at the end to add a new entry
* ``python_releases.txt``: Python release dates 2.5.0-3.6.0

Cache files:

* ``commit_dates.txt``
* ``commit_tags.txt``

Build the doc::

    make

After a release, get new commit tags using::

    make update

For a X.Y.0 release, add X.Y to ``MAINTAINED_BRANCHES`` of ``render_doc.py``.

Build without Makefile::

    ./venv.sh
    ./venv/bin/python render_doc.py
    sphinx-build -M html . build

For ReadTheDocs.org, other files are used:

* ``requirements.txt``
* ``setup.py``: run render_doc.py
