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


Security vulnerabilities
========================

+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+
| Bug              | Disclosure | Fixed In            | Vulnerable          | Comment                                                           |
+==================+============+=====================+=====================+===================================================================+
| `CVE-2016-0772`_ | 2016-06-11 | | 2.7.12 (17 days)  | | 2.7.0-2.7.11      | Fix smtplib TLS stripping                                         |
|                  |            | | 3.4.5 (16 days)   | | 3.2.0-3.4.4       |                                                                   |
|                  |            | | 3.5.2 (16 days)   | | 3.5.0-3.5.1       |                                                                   |
+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+
| `Issue #26657`_  | 2016-03-28 | | 2.7.12 (92 days)  | | 2.7.0-2.7.11      | Fix directory traversal vulnerability with http.server on         |
|                  |            | | 3.5.2 (91 days)   | | 3.3.5-3.5.1       | Windows. Regression of Python 3.3.5.                              |
+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+
| `CVE-2015-1283`_ | 2015-07-24 | | 2.7.12 (340 days) | | 2.7.0-2.7.11      | Update expat to 2.1.1. Multiple integer overflows have been       |
|                  |            | | 3.4.5 (339 days)  | | 3.2.0-3.4.4       | discovered in Expat.                                              |
|                  |            | | 3.5.2 (339 days)  | | 3.5.0-3.5.1       |                                                                   |
+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+
| `CVE-2016-5699`_ | 2014-11-24 | | 2.7.10 (180 days) | | 2.7.0-2.7.9       | HTTP header injection in urrlib2/urllib/httplib/http.client       |
|                  |            | | 3.4.4 (392 days)  | | 3.2.0-3.4.3       |                                                                   |
+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+
| `Hash DoS`_      | 2011-12-28 | | 2.6.8 (104 days)  | | 2.6.0-2.6.7       | Hash collision denial of service. Python 2 requires -R option     |
|                  |            | | 2.7.3 (103 days)  | | 2.7.0-2.7.2       | to enable the fix.                                                |
|                  |            | | 3.1.5 (102 days)  | | 3.1.0-3.1.4       |                                                                   |
|                  |            | | 3.2.3 (104 days)  | | 3.2.0-3.2.2       |                                                                   |
+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+
| `CVE-2016-5636`_ | 2016-01-21 | | 2.7.12 (159 days) | | 2.7.0-2.7.11      | Heap overflow in zipimporter module.                              |
|                  |            | | 3.4.5 (158 days)  | | 3.2.0-3.4.4       |                                                                   |
|                  |            | | 3.5.2 (158 days)  | | 3.5.0-3.5.1       |                                                                   |
+------------------+------------+---------------------+---------------------+-------------------------------------------------------------------+

* Sorted by the Disclosure column
* Disclosure: Disclosure date, first time that the vulnerability was public

Python releases
---------------

See :ref:`Python releases <python-releases>`.

CVE-2016-0772
-------------

* Fix TLS stripping vulnerability in smtplib, CVE-2016-0772.
  Reported by Team Oststrom
* 2.7: change b3ce713fb9be
* 3.4: change d590114c2394
* 2016-06-11: commit in 2.7 and 3.4 branches (and merges)


Issue #26657
------------

* `Issue #26657: Directory traversal with http.server and SimpleHTTPServer on
  Windows <http://bugs.python.org/issue26657>`_, reported at 2016-03-28
* Regression of Python 3.3.5.


CVE-2015-1283
-------------

* Multiple integer overflows have been discovered in Expat, an XML parsing C
  library, which may result in denial of service or the execution of arbitrary
  code if a malformed XML file is processed.
* 2.7: change d8a0a016d8d4
* 2015-07-24: expat bug #528 reported
* https://sourceforge.net/p/expat/bugs/528/
* http://bugs.python.org/issue26556
* https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1283


CVE-2016-5699
-------------

* HTTP header injection in urrlib2/urllib/httplib/http.client
* https://bugs.python.org/issue22928


Hash DoS
--------

* "Effective Denial of Service attacks against web application platforms" talk
  at the CCC: 2011-12-28
* http://www.ocert.org/advisories/ocert-2011-003.html
* `Issue #13703: Hash collision security issue
  <http://bugs.python.org/issue13703>`_
* `PEP 456: Secure and interchangeable hash algorithm
  <https://www.python.org/dev/peps/pep-0456/>`_

CVE-2016-5636
-------------

* Heap overflow in zipimporter module
* https://bugs.python.org/issue26171 reported at 2016-01-21
