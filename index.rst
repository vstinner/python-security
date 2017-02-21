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
   ssl
   python_releases


Python branches
===============

* Python 2.6, 3.0 and 3.1 don't get security fixes anymore and so should be
  considered as vulnerable
* Branches getting security fixes: 2.7, 3.2, 3.3, 3.4 and 3.5
* See `Status of Python branches
  <https://docs.python.org/devguide/#status-of-python-branches>`_


Dangerous functions
===================

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

For example, the ``marshal`` doesn't validate inputs.

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


RNG
===

* CSPRNG:

  * ``os.urandom()``
  * ``random.SystemRandom``
  * `secrets module <https://docs.python.org/dev/library/secrets.html>`_
    (Python 3.6)

* ``os.urandom()`` uses:

  * Python 3.6: ``CryptGenRandom()``, ``getentropy()``,
    ``getrandom(0)`` (blocking) or ``/dev/urandom``
  * Python 3.5: ``CryptGenRandom()``, ``getentropy()``,
    ``getrandom(GRND_NONBLOCK)`` (non-blocking) or ``/dev/urandom``
  * Python 2.7: ``CryptGenRandom()``, ``getentropy()`` or ``/dev/urandom``
  * `PEP 524: Make os.urandom() blocking on Linux
    <https://www.python.org/dev/peps/pep-0524/>`_: Python 3.6


* ``ssl.RAND_bytes()`` fork issue:

  - Python issue: `Re-seed OpenSSL's PRNG after fork
    <http://bugs.python.org/issue18747>`_
  - `OpenSSL Random fork-safety
    <https://wiki.openssl.org/index.php/Random_fork-safety>`_

The ``random`` module must not be used in security sensitive code, except of
the ``random.SystemRandom`` class.


CPython Security Experts
========================

* Alex Gaynor
* Antoine Pitrou
* Christian Heimes
* Donald Stufft

Misc
====

* The ``pickle`` module executes arbitrary Python code: never use it with
  untrusted data.
* `python3 -E <https://docs.python.org/3/using/cmdline.html#cmdoption-E>`_:
  ignore ``PYTHON*`` environment variables like ``PYTHONPATH``
* `python3 -I <https://docs.python.org/3/using/cmdline.html#cmdoption-I>`_:
  isolated mode, also implies ``-E`` and ``-s``
* Python 3.7 adds a ``is_safe`` attribute to uuid.UUID objects:
  http://bugs.python.org/issue22807
* XML: `defusedxml <https://pypi.python.org/pypi/defusedxml>`_, XML bomb
  protection for Python stdlib modules
* Coverity:

  - `Coverity Scan: Python <https://scan.coverity.com/projects/python>`_
  - `devguide info about Coverity <https://docs.python.org/devguide/coverity.html>`_
  - `analysis of 2012 by Coverity Software resulted in CPython receiving their
    highest quality rating
    <http://www.coverity.com/press-releases/coverity-finds-python-sets-new-level-of-quality-for-open-source-software/>`_.

* Windows: ASLR and DEP protections enabled since Python 3.4 (and Python 2.7.11
  if built using ``PCbuild/`` directory)
* sys.path:

  * CVE-2008-5983: http://bugs.python.org/issue5753 added ``PySys_SetArgvEx()``
  * `CVE-2015-5652 <http://www.cvedetails.com/cve/CVE-2015-5652/>`_:
    Untrusted search path vulnerability in python.exe in Python through 3.5.0
    on Windows allows local users to gain privileges via a Trojan horse
    readline.pyd file in the current working directory. NOTE: the vendor says
    "It was determined that this is a longtime behavior of Python that cannot
    really be altered at this point."
  * ``python -E``, ``python -I``

Links
=====

* `The Python security response team
  <https://lwn.net/Articles/691308/>`_ (June, 2016)
* `Reporting security issues in Python
  <https://www.python.org/news/security/>`_
* `OWASP Python Security Project (pythonsecurity.org)
  <http://www.pythonsecurity.org/>`_
* `bandit: Python AST-based static analyzer from OpenStack Security Group
  <https://github.com/openstack/bandit>`_
* `Python CVEs (cvedetails.com)
  <http://www.cvedetails.com/product/18230/Python-Python.html?vendor_id=10210>`_
* https://github.com/pyupio/safety-db and https://pyup.io/
