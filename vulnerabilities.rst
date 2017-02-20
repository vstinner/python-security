++++++++++++++++++++++++
Security vulnerabilities
++++++++++++++++++++++++

Security vulnerabilities
========================

+----------------------------+----------------------------------+--------------+----------------------------+
| Vulnerability              | Summary                          | Disclosure   | Fixed In                   |
+============================+==================================+==============+============================+
| `Issue #28563`_            | ``gettext.c2py()``               | 2016-10-30   | 2.7.13, 3.4.6, 3.5.3       |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2016-1000110`_        | HTTPoxy attack                   | 2016-07-18   | 2.7.13, 3.4.6, 3.5.3       |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2016-0772`_           | smtplib TLS stripping            | 2016-06-11   | 2.7.12, 3.4.5, 3.5.2       |
+----------------------------+----------------------------------+--------------+----------------------------+
| `Issue #26657`_            | HTTP directory traversal         | 2016-03-28   | 2.7.12, 3.5.2              |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2016-5636`_           | zipimporter heap overflow        | 2016-01-21   | 2.7.12, 3.4.5, 3.5.2       |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2015-1283`_           | expat 2.1.1                      | 2015-07-24   | 2.7.12, 3.4.5, 3.5.2       |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2016-5699`_           | HTTP header                      | 2014-11-24   | 2.7.10, 3.4.4              |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2014-4616`_           | JSON arbitrary memory access     | 2014-04-13   | 2.7.7, 3.2.6, 3.3.6, 3.4.1 |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2013-1752 (ftplib)`_  | ftplib readline                  | 2012-09-25   | 2.7.6, 3.2.6, 3.3.3        |
+----------------------------+----------------------------------+--------------+----------------------------+
| `CVE-2013-1752 (smtplib)`_ | smtplib readline                 | 2012-09-25   | 2.7.9, 3.2.6, 3.4.3        |
+----------------------------+----------------------------------+--------------+----------------------------+
| `Issue #16040`_            | nntplib readline                 | 2012-09-25   | 2.6.9, 2.7.6, 3.2.6, 3.4.3 |
+----------------------------+----------------------------------+--------------+----------------------------+
| `Issue #16041`_            | poplib readline                  | 2012-09-25   | 2.7.9, 3.2.6, 3.4.3        |
+----------------------------+----------------------------------+--------------+----------------------------+
| `Issue #16043`_            | xmlrpc unlimited read            | 2012-09-25   | 2.7.9, 3.4.3               |
+----------------------------+----------------------------------+--------------+----------------------------+
| `Hash DoS`_                | Hash collision denial of service | 2011-12-28   | 2.6.8, 2.7.3, 3.1.5, 3.2.3 |
+----------------------------+----------------------------------+--------------+----------------------------+
| `Issue #6791`_             | httplib readline                 | 2009-08-28   | 2.7.2, 3.1.4               |
+----------------------------+----------------------------------+--------------+----------------------------+

* Vulnerabilities sorted by the Disclosure column
* Disclosure: Disclosure date, first time that the vulnerability was public


Issue #28563
============

Disclosure date: 2016-10-30 (issue #28563 reported).

Arbitrary code execution in ``gettext.c2py()``.

Fixed In:

* 2.7.13 (48 days): 2016-12-17, `commit a876027 <https://github.com/python/cpython/commit/a8760275bd59fb8d8be1f1bf05313fed31c08321>`_ (2016-11-08, 9 days)
* 3.4.6 (79 days): 2017-01-17, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08, 9 days)
* 3.5.3 (79 days): 2017-01-17, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08, 9 days)

Links:

* http://bugs.python.org/issue28563


CVE-2016-1000110
================

Disclosure date: 2016-07-18 (issue #27568 reported).

Prevent HTTPoxy attack (CVE-2016-1000110).
Ignore the HTTP_PROXY variable when REQUEST_METHOD environment is set, which indicates that the script is in CGI mode.
Issue #27568 Reported and patch contributed by Rémi Rampin.

Fixed In:

* 2.7.13 (152 days): 2016-12-17, `commit 75d7b61 <https://github.com/python/cpython/commit/75d7b615ba70fc5759d16dee95bbd8f0474d8a9c>`_ (2016-07-30, 12 days)
* 3.4.6 (183 days): 2017-01-17, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-30, 12 days)
* 3.5.3 (183 days): 2017-01-17, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-30, 12 days)

Links:

* http://bugs.python.org/issue27568
* https://httpoxy.org/


CVE-2016-0772
=============

Disclosure date: 2016-06-11 (commit date).

Fix smtplib TLS stripping. Reported by Tin (Team Oststrom).

Fixed In:

* 2.7.12 (17 days): 2016-06-28, `commit 2e1b7fc <https://github.com/python/cpython/commit/2e1b7fc998e1744eeb3bb31b131eba0145b88a2f>`_ (2016-06-11, 0 days)
* 3.4.5 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11, 0 days)
* 3.5.2 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11, 0 days)

Links:

* http://seclists.org/oss-sec/2016/q2/541
* https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-0772


Issue #26657
============

Disclosure date: 2016-03-28 (issue #26657 reported).

Fix directory traversal vulnerability with http.server and SimpleHTTPServer on Windows. Regression of Python 3.3.5.

Fixed In:

* 2.7.12 (92 days): 2016-06-28, `commit 0cf2cf2 <https://github.com/python/cpython/commit/0cf2cf2b7d726d12a6046441e4067d32c7dd4feb>`_ (2016-04-18, 21 days)
* 3.5.2 (91 days): 2016-06-27, `commit d274b3f <https://github.com/python/cpython/commit/d274b3f1f1e2d8811733fb952c9f18d7da3a376a>`_ (2016-04-18, 21 days)

Links:

* http://bugs.python.org/issue26657


CVE-2016-5636
=============

Disclosure date: 2016-01-21 (issue #26171 reported).

Heap overflow in zipimporter module.

Fixed In:

* 2.7.12 (159 days): 2016-06-28, `commit 64ea192 <https://github.com/python/cpython/commit/64ea192b73e39e877d8b39ce6584fa580eb0e9b4>`_ (2016-01-20, -1 days)
* 3.4.5 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-20, -1 days)
* 3.5.2 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-20, -1 days)

Links:

* https://bugs.python.org/issue26171


CVE-2015-1283
=============

Disclosure date: 2015-07-24 (expat issue reported).

Multiple integer overflows have been discovered in Expat, an XML parsing C library, which may result in denial of service or the execution of arbitrary code if a malformed XML file is processed.
Update Expat to 2.1.1.

Fixed In:

* 2.7.12 (340 days): 2016-06-28, `commit d244a8f <https://github.com/python/cpython/commit/d244a8f7cb0ec6979ec9fc7acd39e95f5339ad0e>`_ (2016-06-11, 323 days)
* 3.4.5 (339 days): 2016-06-27, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_ (2016-06-11, 323 days)
* 3.5.2 (339 days): 2016-06-27, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_ (2016-06-11, 323 days)

Links:

* http://bugs.python.org/issue26556
* https://sourceforge.net/p/expat/bugs/528/
* https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1283


CVE-2016-5699
=============

Disclosure date: 2014-11-24 (issue #22928 reported).

HTTP header injection in urrlib2/urllib/httplib/http.client

Fixed In:

* 2.7.10 (180 days): 2015-05-23, `commit 59bdf63 <https://github.com/python/cpython/commit/59bdf6392de446de8a19bfa37cee52981612830e>`_ (2015-03-12, 108 days)
* 3.4.4 (392 days): 2015-12-21, `commit a112a8a <https://github.com/python/cpython/commit/a112a8ae47813f75aa8ad27ee8c42a7c2e937d13>`_ (2015-03-12, 108 days)

Links:

* https://bugs.python.org/issue22928


CVE-2014-4616
=============

Disclosure date: 2014-04-13 (commit).

Fix arbitrary memory access in JSONDecoder.raw_decode with a negative second parameter.
Bug reported by Guido Vranken.

Fixed In:

* 2.7.7 (48 days): 2014-05-31, `commit 6c939cb <https://github.com/python/cpython/commit/6c939cb6f6dfbd273609577b0022542d31ae2802>`_ (2014-04-13, 0 days)
* 3.2.6 (181 days): 2014-10-11, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-13, 0 days)
* 3.3.6 (181 days): 2014-10-11, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-13, 0 days)
* 3.4.1 (35 days): 2014-05-18, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-13, 0 days)


CVE-2013-1752 (ftplib)
======================

Disclosure date: 2012-09-25 (issue #16038 reported).

ftplib: unlimited readline() from connection.
Reported by Christian Heimes.

Fixed In:

* 2.7.6 (411 days): 2013-11-10, `commit 2585e1e <https://github.com/python/cpython/commit/2585e1e48abb3013abeb8a1fe9dccb5f79ac4091>`_ (2013-10-20, 390 days)
* 3.2.6 (746 days): 2014-10-11, `commit c9cb18d <https://github.com/python/cpython/commit/c9cb18d3f7e5bf03220c213183ff0caa75905bdd>`_ (2014-09-30, 735 days)
* 3.3.3 (418 days): 2013-11-17, `commit c30b178 <https://github.com/python/cpython/commit/c30b178cbc92e62c22527cd7e1af2f02723ba679>`_ (2013-10-20, 390 days)

Links:

* http://bugs.python.org/issue16038


CVE-2013-1752 (smtplib)
=======================

Disclosure date: 2012-09-25 (issue #16042 reported).

CVE-2013-1752: The smtplib module doesn't limit the amount of read data in its call to readline(). An erroneous or malicious SMTP server can trick the smtplib module to consume large amounts of memory.

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit dabfc56 <https://github.com/python/cpython/commit/dabfc56b57f5086eb5522d8e6cd7670c62d2482d>`_ (2014-12-05, 801 days)
* 3.2.6 (746 days): 2014-10-11, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30, 735 days)
* 3.4.3 (881 days): 2015-02-23, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30, 735 days)

Links:

* http://bugs.python.org/issue16042


Issue #16040
============

Disclosure date: 2012-09-25 (issue #16040 reported).

Unlimited read from connection in nntplib.

Fixed In:

* 2.6.9 (399 days): 2013-10-29, `commit 42faa55 <https://github.com/python/cpython/commit/42faa55124abcbb132c57745dec9e0489ac74406>`_ (2013-09-30, 370 days)
* 2.7.6 (411 days): 2013-11-10, `commit 42faa55 <https://github.com/python/cpython/commit/42faa55124abcbb132c57745dec9e0489ac74406>`_ (2013-09-30, 370 days)
* 3.2.6 (746 days): 2014-10-11, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12, 747 days)
* 3.4.3 (881 days): 2015-02-23, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12, 747 days)

Links:

* http://bugs.python.org/issue16040


Issue #16041
============

Disclosure date: 2012-09-25 (iIssue #16041 reported).

poplib: unlimited readline() from connection.

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit faad6bb <https://github.com/python/cpython/commit/faad6bbea6c86e30c770eb0a3648e2cd52b2e55e>`_ (2014-12-05, 801 days)
* 3.2.6 (746 days): 2014-10-11, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30, 735 days)
* 3.4.3 (881 days): 2015-02-23, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30, 735 days)

Links:

* http://bugs.python.org/issue16041


Issue #16043
============

Disclosure date: 2012-09-25 (issue #16043 reported).

Add a default limit for the amount of data xmlrpclib.gzip_decode will return.

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit 9e8f523 <https://github.com/python/cpython/commit/9e8f523c5b1c354097753084054eadf14d33238d>`_ (2014-12-05, 801 days)
* 3.4.3 (881 days): 2015-02-23, `commit 4e9cefa <https://github.com/python/cpython/commit/4e9cefaf86035f8014e09049328d197b6506532f>`_ (2014-12-05, 801 days)

Links:

* http://bugs.python.org/issue16043


Hash DoS
========

Disclosure date: 2011-12-28 (CCC talk).

Hash collision denial of service.
Python 2 requires ``-R`` option to enable the fix.
"Effective Denial of Service attacks against web application platforms" talk at the CCC: 2011-12-28

Fixed In:

* 2.6.8 (104 days): 2012-04-10, `commit 1e13eb0 <https://github.com/python/cpython/commit/1e13eb084f72d5993cbb726e45b36bdb69c83a24>`_ (2012-02-20, 54 days)
* 2.7.3 (103 days): 2012-04-09, `commit 1e13eb0 <https://github.com/python/cpython/commit/1e13eb084f72d5993cbb726e45b36bdb69c83a24>`_ (2012-02-20, 54 days)
* 3.1.5 (102 days): 2012-04-08, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_ (2012-02-20, 54 days)
* 3.2.3 (104 days): 2012-04-10, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_ (2012-02-20, 54 days)

Links:

* http://bugs.python.org/issue13703
* https://events.ccc.de/congress/2011/Fahrplan/events/4680.en.html
* https://www.python.org/dev/peps/pep-0456/
* http://www.ocert.org/advisories/ocert-2011-003.html


Issue #6791
===========

Disclosure date: 2009-08-28 (issue #6791 reported).

Limit the HTTP header readline. Reported by sumar (m.sucajtys).

Fixed In:

* 2.7.2 (652 days): 2011-06-11, `commit d7b6ac6 <https://github.com/python/cpython/commit/d7b6ac66c1b81d13f2efa8d9ebba69e17c158c0a>`_ (2010-12-18, 477 days)
* 3.1.4 (652 days): 2011-06-11, `commit ff1bbba <https://github.com/python/cpython/commit/ff1bbba92aad261df1ebd8fd8cc189c104e113b0>`_ (2010-12-18, 477 days)

Links:

* http://bugs.python.org/issue6791
