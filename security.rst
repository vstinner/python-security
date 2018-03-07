+++++++++++++++
Python Security
+++++++++++++++

Python branches
===============

* (Latest update: 2017-03-28) Python 2.6, 3.0, 3.1, 3.2 don't get security
  fixes anymore and so should be considered as vulnerable
* Branches getting security fixes: 2.7, 3.3, 3.4 and 3.5
* See `Status of Python branches
  <https://docs.python.org/devguide/#status-of-python-branches>`_


Dangerous functions and modules
===============================

* Python 2 input()
* Python 2 execfile()
* eval()
* subprocess.Popen(shell=True)
* str.format(), Python 3 str.format_map, and Python 2 unicode.format() all
  allow arbitrary attribute access on formatted values, and hence access
  to Python's introspection features:
  `Be Careful with Python's New-Style String Format
  <http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/>`_
  (Armin Ronacher, December 2016)
* The ``pickle`` module executes arbitrary Python code: never use it with
  untrusted data.
* archives:

  * tarfile: Never extract archives from untrusted sources without prior
    inspection. It is possible that files are created outside of path, e.g.
    members that have absolute filenames starting with "/" or filenames with
    two dots "..".
  * zipfile: Never extract archives from untrusted sources without prior
    inspection. It is possible that files are created outside of path, e.g.
    members that have absolute filenames starting with "/" or filenames with
    two dots "..". zipfile attempts to prevent that.


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

Windows
=======

ASLR and DEP
------------

ASLR and DEP protections enabled since Python 3.4 (and Python 2.7.11 if built
using ``PCbuild/`` directory).

Unsafe Python 2.7 default installation directory
------------------------------------------------

Python 2.7 installer uses C:\Python27\ directory by default. The created
directory has the "Modify" access rights given to the "Authenticated Users"
group. An attacker can modify the standard library or even modify
python.exe. Python 3 installer now installs Python in ``C:\Program Files`` by
default to fix this issue. Override the default installation directory, or
fix the directory permissions.

DLL injection
-------------

On Windows 8.1 and older, the installer is vulnerable to DLL injection:
evil DLL written in the same download directory that the downloaded Python
installer. See `DLL Hijacking Just Won’t Die
<https://textslashplain.com/2015/12/18/dll-hijacking-just-wont-die/>`_.

DLL injection using PATH
------------------------

Inject a malicious DLL in a writable directory included in PATH. The "pip" step
of the Python installer will run this DLL.

We consider that it is not an issue of Python (Python installer) itself.

Once you have write access to a directory on the system PATH (not the current
user PATH) and the ability to write binaries that are not validated by the
operating system before loading, there are many more interesting things you can
do rather than wait for the Python installer to be run.


Misc
====

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

* sys.path:

  * CVE-2008-5983: http://bugs.python.org/issue5753 added ``PySys_SetArgvEx()``
  * `CVE-2015-5652 <http://www.cvedetails.com/cve/CVE-2015-5652/>`_:
    Untrusted search path vulnerability in python.exe in Python through 3.5.0
    on Windows allows local users to gain privileges via a Trojan horse
    readline.pyd file in the current working directory. NOTE: the vendor says
    "It was determined that this is a longtime behavior of Python that cannot
    really be altered at this point."
  * ``python -E``, ``python -I``

* `Python at HackerOne <https://hackerone.com/python>`_
* `humans.txt of python.org <https://www.python.org/humans.txt>`_
  with the list of "people who found security bugs in the website".
  For the rationale, see `humanstxt.org <http://humanstxt.org/>`_.

Python Security Response Team (PSRT)
====================================

* Handle security@python.org incoming emails
* `PSRT issues (private) <https://github.com/python/psrt/issues>`_
* `LWN: The Python security response team
  <https://lwn.net/Articles/691308/>`_ (June, 2016)

Links
=====

* `Reporting security issues in Python
  <https://www.python.org/news/security/>`_
* `Python Security Announce <https://mail.python.org/mm3/mailman3/lists/security-announce.python.org/>`_ 
  public mailing list
* `OWASP Python Security Project (pythonsecurity.org)
  <http://www.pythonsecurity.org/>`_
* `bandit: Python AST-based static analyzer from OpenStack Security Group
  <https://github.com/openstack/bandit>`_
* `Python CVEs (cvedetails.com)
  <http://www.cvedetails.com/product/18230/Python-Python.html?vendor_id=10210>`_
* https://gemnasium.com/
* `owasp-pysec: OWASP Python Security Project
  <https://github.com/ebranca/owasp-pysec>`_
* `LWN: Python ssl module update
  <https://lwn.net/Articles/724209/>`_ by Christian Heimes at the Python
  Language Summit 2017 (during Pycon US, Portland, OR)
