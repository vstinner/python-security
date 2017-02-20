++++++++++++++++++++++++
Security vulnerabilities
++++++++++++++++++++++++

Security vulnerabilities
========================

+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Vulnerability    | Disclosure   | Fixed In                   | Description                                                                                                                                                                                                               |
+==================+==============+============================+===========================================================================================================================================================================================================================+
| `CVE-2016-0772`_ | 2016-06-11   | 2.7.12, 3.4.5, 3.5.2       | Fix smtplib TLS stripping. Reported by Tin (Team Oststrom).                                                                                                                                                               |
+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| `Issue #26657`_  | 2016-03-28   | 2.7.12, 3.5.2              | Fix directory traversal vulnerability with http.server and SimpleHTTPServer on Windows. Regression of Python 3.3.5.                                                                                                       |
+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| `CVE-2016-5636`_ | 2016-01-21   | 2.7.12, 3.4.5, 3.5.2       | Heap overflow in zipimporter module.                                                                                                                                                                                      |
+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| `CVE-2015-1283`_ | 2015-07-24   | 2.7.12, 3.4.5, 3.5.2       | Multiple integer overflows have been discovered in Expat, an XML parsing C library, which may result in denial of service or the execution of arbitrary code if a malformed XML file is processed. Update Expat to 2.1.1. |
+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| `CVE-2016-5699`_ | 2014-11-24   | 2.7.10, 3.4.4              | HTTP header injection in urrlib2/urllib/httplib/http.client                                                                                                                                                               |
+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| `Hash DoS`_      | 2011-12-28   | 2.6.8, 2.7.3, 3.1.5, 3.2.3 | Hash collision denial of service. Python 2 requires -R option to enable the fix. "Effective Denial of Service attacks against web application platforms" talk at the CCC: 2011-12-28                                      |
+------------------+--------------+----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

* Vulnerabilities sorted by the Disclosure column
* Disclosure: Disclosure date, first time that the vulnerability was public


CVE-2016-0772
=============

Disclosure date: 2016-06-11 (commit date).

Fix smtplib TLS stripping. Reported by Tin (Team Oststrom).

Fixed In:

* 2.7.12 (17 days): 2016-06-28, `commit 2e1b7fc <https://github.com/python/cpython/commit/2e1b7fc998e1744eeb3bb31b131eba0145b88a2f>`_
* 3.4.5 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_
* 3.5.2 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_

Links:

* http://seclists.org/oss-sec/2016/q2/541
* https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-0772


Issue #26657
============

Disclosure date: 2016-03-28 (issue reported).

Fix directory traversal vulnerability with http.server and SimpleHTTPServer on Windows. Regression of Python 3.3.5.

Fixed In:

* 2.7.12 (92 days): 2016-06-28, `commit 0cf2cf2 <https://github.com/python/cpython/commit/0cf2cf2b7d726d12a6046441e4067d32c7dd4feb>`_
* 3.5.2 (91 days): 2016-06-27, `commit d274b3f <https://github.com/python/cpython/commit/d274b3f1f1e2d8811733fb952c9f18d7da3a376a>`_

Links:

* http://bugs.python.org/issue26657


CVE-2016-5636
=============

Disclosure date: 2016-01-21 (issue reported).

Heap overflow in zipimporter module.

Fixed In:

* 2.7.12 (159 days): 2016-06-28, `commit 64ea192 <https://github.com/python/cpython/commit/64ea192b73e39e877d8b39ce6584fa580eb0e9b4>`_
* 3.4.5 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_
* 3.5.2 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_

Links:

* https://bugs.python.org/issue26171


CVE-2015-1283
=============

Disclosure date: 2015-07-24 (expat issue reported).

Multiple integer overflows have been discovered in Expat, an XML parsing C library, which may result in denial of service or the execution of arbitrary code if a malformed XML file is processed.
Update Expat to 2.1.1.

Fixed In:

* 2.7.12 (340 days): 2016-06-28, `commit d244a8f <https://github.com/python/cpython/commit/d244a8f7cb0ec6979ec9fc7acd39e95f5339ad0e>`_
* 3.4.5 (339 days): 2016-06-27, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_
* 3.5.2 (339 days): 2016-06-27, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_

Links:

* http://bugs.python.org/issue26556
* https://sourceforge.net/p/expat/bugs/528/
* https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1283


CVE-2016-5699
=============

Disclosure date: 2014-11-24 (issue reported).

HTTP header injection in urrlib2/urllib/httplib/http.client

Fixed In:

* 2.7.10 (180 days): 2015-05-23, `commit 59bdf63 <https://github.com/python/cpython/commit/59bdf6392de446de8a19bfa37cee52981612830e>`_
* 3.4.4 (392 days): 2015-12-21, `commit a112a8a <https://github.com/python/cpython/commit/a112a8ae47813f75aa8ad27ee8c42a7c2e937d13>`_

Links:

* https://bugs.python.org/issue22928


Hash DoS
========

Disclosure date: 2011-12-28 (CCC talk).

Hash collision denial of service.
Python 2 requires -R option to enable the fix.
"Effective Denial of Service attacks against web application platforms" talk at the CCC: 2011-12-28

Fixed In:

* 2.6.8 (104 days): 2012-04-10, `commit 1e13eb0 <https://github.com/python/cpython/commit/1e13eb084f72d5993cbb726e45b36bdb69c83a24>`_
* 2.7.3 (103 days): 2012-04-09, `commit 1e13eb0 <https://github.com/python/cpython/commit/1e13eb084f72d5993cbb726e45b36bdb69c83a24>`_
* 3.1.5 (102 days): 2012-04-08, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_
* 3.2.3 (104 days): 2012-04-10, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_

Links:

* http://bugs.python.org/issue13703
* https://events.ccc.de/congress/2011/Fahrplan/events/4680.en.html
* https://www.python.org/dev/peps/pep-0456/
* http://www.ocert.org/advisories/ocert-2011-003.html
