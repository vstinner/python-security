+++++++++++++++
Python Security
+++++++++++++++

This page is an attempt to document security vulnerabilities in Python and the
versions including the fix.

Pages
=====

.. toctree::
   :maxdepth: 2

   vulnerabilities
   python_releases

Python branches
===============

* Python 2.6, 3.0 and 3.1 don't get security fixes anymore and so should be
  considered as vulnerable
* Branches getting security fixes: 2.7, 3.2, 3.3, 3.4 and 3.5
* See `Status of Python branches
  <https://docs.python.org/devguide/#status-of-python-branches>`_

Bases
=====

* Python 2 input()
* Python 2 execfile()
* eval()
* subprocess.Popen(shell=True)
* Python 3.6 f-string: `Be Careful with Python's New-Style String Format
  <http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/>`_
  (Armin Ronacher, December 2016)


Security model
==============

Bytecode
--------

CPython doesn't verify that bytecode is safe. If an attacker is able to
execute arbitrary bytecode, we consider that the security of the bytecode is
the least important issue: using bytecode, sensitive code can be imported and
executed.

Sandbox
-------

Don't try to build a sandbox inside CPython. The attack surface is too large.
Python has many introspection features, see for example the ``inspect`` module.
Python also many convenient features which executes code on demand. Examples:

* the literal string ``'\N{Snowman}'`` imports the ``unicodedata`` module
* the code to log a warning might be abused to execute code

The good design is to put CPython into a sandbox, not the opposite.

Ok, understood, but I want a sandbox in Python. Well...

* `Eval really is dangerous
  <http://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html>`_
  (Ned Batchelder, June 2012)
* `PyPy sandboxing <http://pypy.org/features.html#sandboxing>`_
* For Linux, search for SECCOMP


Misc
====

* `python3 -E <https://docs.python.org/3/using/cmdline.html#cmdoption-E>`_:
  ignore ``PYTHON*`` environment variables like ``PYTHONPATH``
* `python3 -I <https://docs.python.org/3/using/cmdline.html#cmdoption-I>`_:
  isolated mode, also implies ``-E`` and ``-s``
* Python 3.7 adds a ``is_safe`` attribute to uuid.UUID objects:
  http://bugs.python.org/issue22807
* XML: `defusedxml https://pypi.python.org/pypi/defusedxml>`_, XML bomb
  protection for Python stdlib modules
* Coverity:

  - `Coverity Scan: Python <https://scan.coverity.com/projects/python>`_
  - `devguide info about Coverity <https://docs.python.org/devguide/coverity.html>`_
  - `analysis of 2012 by Coverity Software resulted in CPython receiving their
    highest quality rating
    <http://www.coverity.com/press-releases/coverity-finds-python-sets-new-level-of-quality-for-open-source-software/>`_.

Links
=====

* `Reporting security issues in Python
  <https://www.python.org/news/security/>`_
* `OWASP Python Security Project (pythonsecurity.org)
  <http://www.pythonsecurity.org/>`_
* `bandit: Python AST-based static analyzer from OpenStack Security Group
  <https://github.com/openstack/bandit>`_
* `cryptography  (cryptography.io) <https://cryptography.io/>`_: Python library
  which exposes cryptographic recipes and primitives
