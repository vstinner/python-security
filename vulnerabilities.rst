++++++++++++++++++++++++
Security vulnerabilities
++++++++++++++++++++++++

Security vulnerabilities
========================

+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| Vulnerability              | Summary                                           | Disclosure   | Score         | Fixed In                                 |
+============================+===================================================+==============+===============+==========================================+
| `Issue #28563`_            | ``gettext.c2py()``                                | 2016-10-30   | ?             | 2.7.13, 3.4.6, 3.5.3, 3.6.0              |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-2183`_           | Sweet32 attack (DES, 3DES)                        | 2016-08-24   | 5.0           | 2.7.13, 3.5.3, 3.6.0                     |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-1000110`_        | HTTPoxy attack                                    | 2016-07-18   | 5.0 (CVSS v3) | 2.7.13, 3.4.6, 3.5.3, 3.6.0              |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-0772`_           | smtplib TLS stripping                             | 2016-06-11   | 5.8           | 2.7.12, 3.4.5, 3.5.2, 3.6.0              |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `Issue #26657`_            | HTTP directory traversal                          | 2016-03-28   | ?             | 2.7.12, 3.5.2, 3.6.0                     |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-5636`_           | zipimporter heap overflow                         | 2016-01-21   | 10.0          | 2.7.12, 3.4.5, 3.5.2, 3.6.0              |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2015-1283`_           | expat 2.1.1                                       | 2015-07-24   | 6.8           | 2.7.12, 3.4.5, 3.5.2, 3.6.0              |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-5699`_           | HTTP header injection                             | 2014-11-24   | 4.3           | 2.7.10, 3.4.4, 3.5.0                     |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-7185`_           | buffer integer overflow                           | 2014-06-24   | 6.4           | 2.7.8                                    |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-9365`_           | Validate TLS certificate                          | 2014-04-19   | 5.8           | 2.7.9, 3.4.3, 3.5.0                      |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-4616`_           | JSON arbitrary memory access                      | 2014-04-13   | Moderate      | 2.7.7, 3.2.6, 3.3.6, 3.4.1, 3.5.0        |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-2667`_           | ``os.makedirs(exist_ok=True)`` is not thread-safe | 2014-03-28   | 3.3           | 3.2.6, 3.3.6, 3.4.1, 3.5.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-1912`_           | ``socket.recvfrom_into()`` buffer overflow        | 2014-01-14   | 7.5           | 2.7.7, 3.2.6, 3.3.4, 3.4.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-7338`_           | zipfile DoS using malformed file                  | 2013-12-27   | 7.1           | 3.3.4, 3.4.0                             |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `Issue #19435`_            | CGIHTTPRequestHandler directory traversal         | 2013-10-29   | ?             | 2.7.6, 3.2.6, 3.3.4, 3.4.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-4238`_           | ssl: NUL in subjectAltNames                       | 2013-08-12   | 4.3           | 2.6.9, 2.7.6, 3.3.3, 3.4.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-7440`_           | ``ssl.match_hostname()`` vuln with IDNA prefix    | 2013-05-17   | 4.3           | 3.3.3, 3.4.0                             |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-2099`_           | ``ssl.match_hostname()`` wildcard                 | 2013-05-15   | 4.3           | 3.3.3, 3.4.0                             |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (ftplib)`_  | ftplib unlimited read                             | 2012-09-25   | Moderate      | 2.7.6, 3.2.6, 3.3.3, 3.4.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (nntplib)`_ | nntplib unlimited read                            | 2012-09-25   | Moderate      | 2.6.9, 2.7.6, 3.2.6, 3.4.3, 3.5.0        |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (poplib)`_  | poplib unlimited read                             | 2012-09-25   | Moderate      | 2.7.9, 3.2.6, 3.4.3, 3.5.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (smtplib)`_ | smtplib unlimited read                            | 2012-09-25   | Moderate      | 2.7.9, 3.2.6, 3.4.3, 3.5.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1753`_           | xmlrpc unlimited read                             | 2012-09-25   | Moderate      | 2.7.9, 3.4.3, 3.5.0                      |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-7040`_           | Hash not randomized properly                      | 2012-04-19   | 4.3           | 3.4.0                                    |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2012-2135`_           | UTF-16 decoder                                    | 2012-04-14   | 6.4           | 2.7.4, 3.2.4, 3.3.0                      |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2012-0845`_           | XML-RPC DoS                                       | 2012-02-13   | 5.0           | 2.6.8, 2.7.3, 3.1.5, 3.2.3, 3.3.0        |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-3389`_           | ssl CBC IV attack                                 | 2012-01-27   | 4.3           | 2.6.8, 2.7.3, 3.1.5, 3.2.3, 3.3.0        |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2012-1150`_           | Hash collision denial of service                  | 2011-12-28   | 5.0           | 2.6.8, 2.7.3, 3.1.5, 3.2.3, 3.3.0        |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-4944`_           | ``~/.pypirc`` created insecurely                  | 2011-11-30   | 1.9           | 2.7.4, 3.2.4, 3.3.1, 3.4.0               |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-1521`_           | urllib redirect vulnerability                     | 2011-03-24   | 6.4           | 2.5.6, 2.6.7, 2.7.2, 3.1.4, 3.2.1, 3.3.0 |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-4940`_           | SimpleHTTPServer UTF-7 vulnerability              | 2011-03-08   | 2.6           | 2.5.6, 2.6.7, 2.7.2, 3.2.4, 3.3.1, 3.4.0 |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `Issue #6791`_             | httplib unlimited read                            | 2009-08-28   | ?             | 2.7.2, 3.1.4, 3.2                        |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-1015`_           | CGIHTTPServer directory traversal                 | 2008-03-07   | 5.0           | 2.7, 3.2.4, 3.3.1, 3.4.0                 |
+----------------------------+---------------------------------------------------+--------------+---------------+------------------------------------------+

* Vulnerabilities sorted by the Disclosure column
* Disclosure: Disclosure date, first time that the vulnerability was public
* `CVSS Score <https://nvd.nist.gov/cvss.cfm>`_
* `Red Hat impact <https://access.redhat.com/security/updates/classification/>`_


Issue #28563
============

Disclosure date: 2016-10-30 (issue #28563 reported).

Arbitrary code execution in ``gettext.c2py()``.

Links:

* http://bugs.python.org/issue28563

Fixed In:

* 2.7.13 (48 days): 2016-12-17, `commit a876027 <https://github.com/python/cpython/commit/a8760275bd59fb8d8be1f1bf05313fed31c08321>`_ (2016-11-08, 9 days)
* 3.4.6 (79 days): 2017-01-17, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08, 9 days)
* 3.5.3 (79 days): 2017-01-17, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08, 9 days)
* 3.6.0: 2016-12-23, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_


CVE-2016-2183
=============

Disclosure date: 2016-08-24 (issue #27850 reported).

`CVSS Score`_: 5.0.

Remove 3DES from ssl default cipher list.
Sweet32 vulnerability found by Karthik Bhargavan and Gaetan Leurent from the `INRIA <https://www.inria.fr/>`_.

Links:

* http://bugs.python.org/issue27850
* https://sweet32.info/
* https://www.openssl.org/blog/blog/2016/08/24/sweet32/
* http://www.cvedetails.com/cve/CVE-2016-2183/

Fixed In:

* 2.7.13 (115 days): 2016-12-17, `commit d988f42 <https://github.com/python/cpython/commit/d988f429fe43808345812ef63dfa8da170c61871>`_ (2016-09-06, 13 days)
* 3.5.3 (146 days): 2017-01-17, `commit 03d13c0 <https://github.com/python/cpython/commit/03d13c0cbfe912eb0f9b9a02987b9e569f25fe19>`_ (2016-09-06, 13 days)
* 3.6.0: 2016-12-23, `commit 03d13c0 <https://github.com/python/cpython/commit/03d13c0cbfe912eb0f9b9a02987b9e569f25fe19>`_


CVE-2016-1000110
================

Disclosure date: 2016-07-18 (issue #27568 reported).

`CVSS Score`_: 5.0 (CVSS v3).

Prevent HTTPoxy attack (CVE-2016-1000110).
Ignore the HTTP_PROXY variable when REQUEST_METHOD environment is set, which indicates that the script is in CGI mode.
Issue #27568 Reported and patch contributed by Rémi Rampin.

Links:

* http://bugs.python.org/issue27568
* https://httpoxy.org/
* https://access.redhat.com/security/cve/cve-2016-1000110
* http://www.cvedetails.com/cve/CVE-2016-1000110/

Fixed In:

* 2.7.13 (152 days): 2016-12-17, `commit 75d7b61 <https://github.com/python/cpython/commit/75d7b615ba70fc5759d16dee95bbd8f0474d8a9c>`_ (2016-07-30, 12 days)
* 3.4.6 (183 days): 2017-01-17, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-31, 13 days)
* 3.5.3 (183 days): 2017-01-17, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-31, 13 days)
* 3.6.0: 2016-12-23, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_


CVE-2016-0772
=============

Disclosure date: 2016-06-11 (commit date).

`CVSS Score`_: 5.8.

A vulnerability in smtplib allowing MITM attacker to perform a startTLS stripping attack. smtplib does not seem to raise an exception when the remote end (SMTP server) is capable of negotiating starttls but fails to respond with 220 (ok) to an explicit call of SMTP.starttls(). This may allow a malicious MITM to perform a startTLS stripping attack if the client code does not explicitly check the response code for startTLS.
Reported by Tin (Team Oststrom).

Links:

* http://seclists.org/oss-sec/2016/q2/541
* https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-0772
* http://www.cvedetails.com/cve/CVE-2016-0772/

Fixed In:

* 2.7.12 (17 days): 2016-06-28, `commit 2e1b7fc <https://github.com/python/cpython/commit/2e1b7fc998e1744eeb3bb31b131eba0145b88a2f>`_ (2016-06-11, 0 days)
* 3.4.5 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11, 0 days)
* 3.5.2 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11, 0 days)
* 3.6.0: 2016-12-23, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_


Issue #26657
============

Disclosure date: 2016-03-28 (issue #26657 reported).

Fix directory traversal vulnerability with http.server and SimpleHTTPServer on Windows. Regression of Python 3.3.5.

Links:

* http://bugs.python.org/issue26657

Fixed In:

* 2.7.12 (92 days): 2016-06-28, `commit 0cf2cf2 <https://github.com/python/cpython/commit/0cf2cf2b7d726d12a6046441e4067d32c7dd4feb>`_ (2016-04-18, 21 days)
* 3.5.2 (91 days): 2016-06-27, `commit d274b3f <https://github.com/python/cpython/commit/d274b3f1f1e2d8811733fb952c9f18d7da3a376a>`_ (2016-04-18, 21 days)
* 3.6.0: 2016-12-23, `commit d274b3f <https://github.com/python/cpython/commit/d274b3f1f1e2d8811733fb952c9f18d7da3a376a>`_


CVE-2016-5636
=============

Disclosure date: 2016-01-21 (issue #26171 reported).

`CVSS Score`_: 10.0.

Heap overflow in zipimporter module.

Links:

* https://bugs.python.org/issue26171
* http://www.cvedetails.com/cve/CVE-2016-5636/

Fixed In:

* 2.7.12 (159 days): 2016-06-28, `commit 64ea192 <https://github.com/python/cpython/commit/64ea192b73e39e877d8b39ce6584fa580eb0e9b4>`_ (2016-01-21, 0 days)
* 3.4.5 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-21, 0 days)
* 3.5.2 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-21, 0 days)
* 3.6.0: 2016-12-23, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_


CVE-2015-1283
=============

Disclosure date: 2015-07-24 (expat issue reported).

`CVSS Score`_: 6.8.

Multiple integer overflows have been discovered in Expat, an XML parsing C library, which may result in denial of service or the execution of arbitrary code if a malformed XML file is processed.
Update Expat to 2.1.1.

Links:

* http://bugs.python.org/issue26556
* https://sourceforge.net/p/expat/bugs/528/
* https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1283
* http://www.cvedetails.com/cve/CVE-2015-1283/

Fixed In:

* 2.7.12 (340 days): 2016-06-28, `commit d244a8f <https://github.com/python/cpython/commit/d244a8f7cb0ec6979ec9fc7acd39e95f5339ad0e>`_ (2016-06-11, 323 days)
* 3.4.5 (339 days): 2016-06-27, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_ (2016-06-11, 323 days)
* 3.5.2 (339 days): 2016-06-27, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_ (2016-06-11, 323 days)
* 3.6.0: 2016-12-23, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_


CVE-2016-5699
=============

Disclosure date: 2014-11-24 (issue #22928 reported).

`CVSS Score`_: 4.3.

HTTP header injection in urllib, urrlib2, httplib and http.client.
CRLF injection vulnerability in the HTTPConnection.putheader function in urllib2 and urllib in CPython (aka Python) before 2.7.10 and 3.x before 3.4.4 allows remote attackers to inject arbitrary HTTP headers via CRLF sequences in a URL.

Links:

* https://bugs.python.org/issue22928
* https://access.redhat.com/security/cve/cve-2014-4616
* http://www.cvedetails.com/cve/CVE-2016-5699/

Fixed In:

* 2.7.10 (180 days): 2015-05-23, `commit 59bdf63 <https://github.com/python/cpython/commit/59bdf6392de446de8a19bfa37cee52981612830e>`_ (2015-03-12, 108 days)
* 3.4.4 (392 days): 2015-12-21, `commit a112a8a <https://github.com/python/cpython/commit/a112a8ae47813f75aa8ad27ee8c42a7c2e937d13>`_ (2015-03-12, 108 days)
* 3.5.0: 2015-09-09, `commit a112a8a <https://github.com/python/cpython/commit/a112a8ae47813f75aa8ad27ee8c42a7c2e937d13>`_


CVE-2014-7185
=============

Disclosure date: 2014-06-24 (issue #21831 reported).

`CVSS Score`_: 6.4.

Integer overflow in bufferobject.c in Python before 2.7.8 allows context-dependent attackers to obtain sensitive information from process memory via a large size and offset in a ``buffer`` type.
Reported by Chris Foster on the Python security list:

Links:

* http://bugs.python.org/issue21831
* http://www.cvedetails.com/cve/CVE-2014-7185/

Fixed In:

* 2.7.8 (5 days): 2014-06-29, `commit 550b945 <https://github.com/python/cpython/commit/550b945fd66f1c6837a53fbf29dc8e524297b8c3>`_ (2014-06-24, 0 days)


CVE-2014-9365
=============

Disclosure date: 2014-04-19 (issue #21308 reported).

`CVSS Score`_: 5.8.

[Python 2] backport many ssl features from Python 3. A contribution of Alex Gaynor and David Reid with the generous support of Rackspace. May God have mercy on their souls.

Links:

* http://bugs.python.org/issue21308
* http://bugs.python.org/issue22417
* https://www.python.org/dev/peps/pep-0466/
* https://www.python.org/dev/peps/pep-0476/
* http://www.cvedetails.com/cve/CVE-2014-9365/

Fixed In:

* 2.7.9 (235 days): 2014-12-10, `commit daeb925 <https://github.com/python/cpython/commit/daeb925cc88cc8fed2030166ade641de28edb396>`_ (2014-08-20, 123 days)
* 3.4.3 (310 days): 2015-02-23, `commit 4ffb075 <https://github.com/python/cpython/commit/4ffb0752710f0c0720d4f2af0c4b7ce1ebb9d2bd>`_ (2014-11-03, 198 days)
* 3.5.0: 2015-09-09, `commit 4ffb075 <https://github.com/python/cpython/commit/4ffb0752710f0c0720d4f2af0c4b7ce1ebb9d2bd>`_


CVE-2014-4616
=============

Disclosure date: 2014-04-13 (commit).

`Red Hat impact`_: Moderate.

Fix arbitrary memory access in JSONDecoder.raw_decode with a negative second parameter.
Bug reported by Guido Vranken.

Links:

* http://bugs.python.org/issue21529
* http://www.cvedetails.com/cve/CVE-2014-4616/

Fixed In:

* 2.7.7 (48 days): 2014-05-31, `commit 6c939cb <https://github.com/python/cpython/commit/6c939cb6f6dfbd273609577b0022542d31ae2802>`_ (2014-04-14, 1 days)
* 3.2.6 (181 days): 2014-10-11, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14, 1 days)
* 3.3.6 (181 days): 2014-10-11, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14, 1 days)
* 3.4.1 (35 days): 2014-05-18, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14, 1 days)
* 3.5.0: 2015-09-09, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_


CVE-2014-2667
=============

Disclosure date: 2014-03-28 (issue #21082 reported).

`CVSS Score`_: 3.3.

``os.makedirs(exist_ok=True)`` is not thread-safe: umask is set temporary to ``0``, serious security problem.
Remove directory mode check from ``os.makedirs()``.
Reported by Ryan Lortie.

Links:

* http://bugs.python.org/issue21082
* http://www.cvedetails.com/cve/CVE-2014-2667/

Fixed In:

* 3.2.6 (197 days): 2014-10-11, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01, 4 days)
* 3.3.6 (197 days): 2014-10-11, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01, 4 days)
* 3.4.1 (51 days): 2014-05-18, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01, 4 days)
* 3.5.0: 2015-09-09, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_


CVE-2014-1912
=============

Disclosure date: 2014-01-14 (issue #20246 reported).

`CVSS Score`_: 7.5.

``socket.recvfrom_into()`` fails to check that the supplied buffer object is big enough for the requested read and so will happily write off the end.
Reported by Ryan Smith-Roberts.

Links:

* http://bugs.python.org/issue20246
* http://www.cvedetails.com/cve/CVE-2014-1912/

Fixed In:

* 2.7.7 (137 days): 2014-05-31, `commit 28cf368 <https://github.com/python/cpython/commit/28cf368c1baba3db1f01010e921f63017af74c8f>`_ (2014-01-14, 0 days)
* 3.2.6 (270 days): 2014-10-11, `commit fbf648e <https://github.com/python/cpython/commit/fbf648ebba32bbc5aa571a4b09e2062a65fd2492>`_ (2014-01-14, 0 days)
* 3.3.4 (26 days): 2014-02-09, `commit fbf648e <https://github.com/python/cpython/commit/fbf648ebba32bbc5aa571a4b09e2062a65fd2492>`_ (2014-01-14, 0 days)
* 3.4.0: 2014-03-16, `commit fbf648e <https://github.com/python/cpython/commit/fbf648ebba32bbc5aa571a4b09e2062a65fd2492>`_


CVE-2013-7338
=============

Disclosure date: 2013-12-27 (issue #20078 reported).

`CVSS Score`_: 7.1.

Python before 3.3.4 RC1 allows remote attackers to cause a denial of service (infinite loop and CPU consumption) via a file size value larger than the size of the zip file to the functions:
* ``ZipExtFile.read()`` * ``ZipExtFile.readlines()`` * ``ZipFile.extract()`` * ``ZipFile.extractall()``
Reading malformed zipfiles no longer hangs with 100% CPU consumption.
Python 2.7 is not affected.
Reported by Nandiya.

Links:

* http://bugs.python.org/issue20078
* http://www.cvedetails.com/cve/CVE-2013-7338/

Fixed In:

* 3.3.4 (44 days): 2014-02-09, `commit 5ce3f10 <https://github.com/python/cpython/commit/5ce3f10aeea711bb912e948fa5d9f63736df1327>`_ (2014-01-09, 13 days)
* 3.4.0: 2014-03-16, `commit 5ce3f10 <https://github.com/python/cpython/commit/5ce3f10aeea711bb912e948fa5d9f63736df1327>`_


Issue #19435
============

Disclosure date: 2013-10-29 (issue #19435 reported).

An error in separating the path and filename of the CGI script to run in http.server.CGIHTTPRequestHandler allows running arbitrary executables in the directory under which the server was started.
Reported by Alexander Kruppa.

Links:

* http://bugs.python.org/issue19435

Fixed In:

* 2.7.6 (12 days): 2013-11-10, `commit 1ef959a <https://github.com/python/cpython/commit/1ef959ac3ddc4d96dfa1a613db5cb206cdaeb662>`_ (2013-10-30, 1 days)
* 3.2.6 (347 days): 2014-10-11, `commit 04e9de4 <https://github.com/python/cpython/commit/04e9de40f380b2695f955d68f2721d57cecbf858>`_ (2013-10-30, 1 days)
* 3.3.4 (103 days): 2014-02-09, `commit 04e9de4 <https://github.com/python/cpython/commit/04e9de40f380b2695f955d68f2721d57cecbf858>`_ (2013-10-30, 1 days)
* 3.4.0: 2014-03-16, `commit 04e9de4 <https://github.com/python/cpython/commit/04e9de40f380b2695f955d68f2721d57cecbf858>`_


CVE-2013-4238
=============

Disclosure date: 2013-08-12 (issue #18709 reported).

`CVSS Score`_: 4.3.

SSL module fails to handle NULL bytes inside subjectAltNames general names.
Reported by Christian Heimes.

Links:

* http://bugs.python.org/issue18709
* http://www.cvedetails.com/cve/CVE-2013-4238/

Fixed In:

* 2.6.9 (78 days): 2013-10-29, `commit 82f8828 <https://github.com/python/cpython/commit/82f88283171933127f20f866a7f98694b29cca56>`_ (2013-08-23, 11 days)
* 2.7.6 (90 days): 2013-11-10, `commit 82f8828 <https://github.com/python/cpython/commit/82f88283171933127f20f866a7f98694b29cca56>`_ (2013-08-23, 11 days)
* 3.3.3 (97 days): 2013-11-17, `commit 824f7f3 <https://github.com/python/cpython/commit/824f7f366d1b54d2d3100c3130c04cf1dfb4b47c>`_ (2013-08-16, 4 days)
* 3.4.0: 2014-03-16, `commit 824f7f3 <https://github.com/python/cpython/commit/824f7f366d1b54d2d3100c3130c04cf1dfb4b47c>`_


CVE-2013-7440
=============

Disclosure date: 2013-05-17 (issue #17997 reported).

`CVSS Score`_: 4.3.

``ssl.match_hostname()``: sub string wildcard should not match IDNA prefix.
Change behavior of ``ssl.match_hostname()`` to follow RFC 6125, for security reasons.  It now doesn't match multiple wildcards nor wildcards inside IDN fragments.
Reported by Christian Heimes.

Links:

* https://bugs.python.org/issue17997
* https://tools.ietf.org/html/rfc6125
* http://www.cvedetails.com/cve/CVE-2013-7440/

Fixed In:

* 3.3.3 (184 days): 2013-11-17, `commit 72c98d3 <https://github.com/python/cpython/commit/72c98d3a761457a4f2b8054458b19f051dfb5886>`_ (2013-10-27, 163 days)
* 3.4.0: 2014-03-16, `commit 72c98d3 <https://github.com/python/cpython/commit/72c98d3a761457a4f2b8054458b19f051dfb5886>`_


CVE-2013-2099
=============

Disclosure date: 2013-05-15 (issue #17980 reported).

`CVSS Score`_: 4.3.

If the name in the certificate contains many ``*`` characters (wildcard), matching the compiled regular expression against the host name can take a very long time.
Certificate validation happens before host name checking, so I think this is a minor issue only because it can only be triggered in cooperation with a CA (which seems unlikely).
Reported by Florian Weimer.

Links:

* http://bugs.python.org/issue17980
* http://www.cvedetails.com/cve/CVE-2013-2099/

Fixed In:

* 3.3.3 (186 days): 2013-11-17, `commit 636f93c <https://github.com/python/cpython/commit/636f93c63ba286249c1207e3a903f8429efb2041>`_ (2013-05-18, 3 days)
* 3.4.0: 2014-03-16, `commit 636f93c <https://github.com/python/cpython/commit/636f93c63ba286249c1207e3a903f8429efb2041>`_


CVE-2013-1752 (ftplib)
======================

Disclosure date: 2012-09-25 (issue #16038 reported).

`Red Hat impact`_: Moderate.

ftplib: unlimited readline() from connection.
Reported by Christian Heimes.

Links:

* http://bugs.python.org/issue16038
* https://access.redhat.com/security/cve/cve-2013-1752

Fixed In:

* 2.7.6 (411 days): 2013-11-10, `commit 2585e1e <https://github.com/python/cpython/commit/2585e1e48abb3013abeb8a1fe9dccb5f79ac4091>`_ (2013-10-20, 390 days)
* 3.2.6 (746 days): 2014-10-11, `commit c9cb18d <https://github.com/python/cpython/commit/c9cb18d3f7e5bf03220c213183ff0caa75905bdd>`_ (2014-09-30, 735 days)
* 3.3.3 (418 days): 2013-11-17, `commit c30b178 <https://github.com/python/cpython/commit/c30b178cbc92e62c22527cd7e1af2f02723ba679>`_ (2013-10-20, 390 days)
* 3.4.0: 2014-03-16, `commit c30b178 <https://github.com/python/cpython/commit/c30b178cbc92e62c22527cd7e1af2f02723ba679>`_


CVE-2013-1752 (nntplib)
=======================

Disclosure date: 2012-09-25 (issue #16040 reported).

`Red Hat impact`_: Moderate.

Unlimited read from connection in nntplib.

Links:

* http://bugs.python.org/issue16040
* https://access.redhat.com/security/cve/cve-2013-1752

Fixed In:

* 2.6.9 (399 days): 2013-10-29, `commit 42faa55 <https://github.com/python/cpython/commit/42faa55124abcbb132c57745dec9e0489ac74406>`_ (2013-09-30, 370 days)
* 2.7.6 (411 days): 2013-11-10, `commit 42faa55 <https://github.com/python/cpython/commit/42faa55124abcbb132c57745dec9e0489ac74406>`_ (2013-09-30, 370 days)
* 3.2.6 (746 days): 2014-10-11, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12, 747 days)
* 3.4.3 (881 days): 2015-02-23, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12, 747 days)
* 3.5.0: 2015-09-09, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_


CVE-2013-1752 (poplib)
======================

Disclosure date: 2012-09-25 (iIssue #16041 reported).

`Red Hat impact`_: Moderate.

poplib: unlimited readline() from connection.

Links:

* http://bugs.python.org/issue16041
* https://access.redhat.com/security/cve/cve-2013-1752

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit faad6bb <https://github.com/python/cpython/commit/faad6bbea6c86e30c770eb0a3648e2cd52b2e55e>`_ (2014-12-06, 802 days)
* 3.2.6 (746 days): 2014-10-11, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30, 735 days)
* 3.4.3 (881 days): 2015-02-23, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30, 735 days)
* 3.5.0: 2015-09-09, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_


CVE-2013-1752 (smtplib)
=======================

Disclosure date: 2012-09-25 (issue #16042 reported).

`Red Hat impact`_: Moderate.

CVE-2013-1752: The smtplib module doesn't limit the amount of read data in its call to readline(). An erroneous or malicious SMTP server can trick the smtplib module to consume large amounts of memory.

Links:

* http://bugs.python.org/issue16042
* https://access.redhat.com/security/cve/cve-2013-1752

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit dabfc56 <https://github.com/python/cpython/commit/dabfc56b57f5086eb5522d8e6cd7670c62d2482d>`_ (2014-12-06, 802 days)
* 3.2.6 (746 days): 2014-10-11, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30, 735 days)
* 3.4.3 (881 days): 2015-02-23, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30, 735 days)
* 3.5.0: 2015-09-09, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_


CVE-2013-1753
=============

Disclosure date: 2012-09-25 (issue #16043 reported).

`Red Hat impact`_: Moderate.

Add a default limit for the amount of data xmlrpclib.gzip_decode will return.

Links:

* http://bugs.python.org/issue16043
* https://access.redhat.com/security/cve/cve-2013-1753
* http://www.cvedetails.com/cve/CVE-2013-1753/

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit 9e8f523 <https://github.com/python/cpython/commit/9e8f523c5b1c354097753084054eadf14d33238d>`_ (2014-12-06, 802 days)
* 3.4.3 (881 days): 2015-02-23, `commit 4e9cefa <https://github.com/python/cpython/commit/4e9cefaf86035f8014e09049328d197b6506532f>`_ (2014-12-06, 802 days)
* 3.5.0: 2015-09-09, `commit 4e9cefa <https://github.com/python/cpython/commit/4e9cefaf86035f8014e09049328d197b6506532f>`_


CVE-2013-7040
=============

Disclosure date: 2012-04-19 (issue #14621 reported).

`CVSS Score`_: 4.3.

Hash function is not randomized properly.
Python 3.4 now used SipHash (PEP 456).
Python 3.3 and Python 2.7 are still affected.
Reported by Vlado Boza.

Links:

* http://bugs.python.org/issue14621
* http://www.cvedetails.com/cve/CVE-2013-7040/

Fixed In:

* 3.4.0 (696 days): 2014-03-16, `commit 985ecdc <https://github.com/python/cpython/commit/985ecdcfc29adfc36ce2339acf03f819ad414869>`_ (2013-11-20, 580 days)


CVE-2012-2135
=============

Disclosure date: 2012-04-14.

`CVSS Score`_: 6.4.

Vulnerability in the UTF-16 decoder after error handling.
Reported by Serhiy Storchaka.

Links:

* http://bugs.python.org/issue14579
* http://www.cvedetails.com/cve/CVE-2012-2135/

Fixed In:

* 2.7.4 (357 days): 2013-04-06, `commit 715a63b <https://github.com/python/cpython/commit/715a63b78349952ccc0fb3dd3139e2d822006d35>`_ (2012-07-20, 97 days)
* 3.2.4 (358 days): 2013-04-07, `commit 715a63b <https://github.com/python/cpython/commit/715a63b78349952ccc0fb3dd3139e2d822006d35>`_ (2012-07-20, 97 days)
* 3.3.0: 2012-09-29, `commit b4bbee2 <https://github.com/python/cpython/commit/b4bbee25b1e3f4bccac222f806b3138fb72439d6>`_


CVE-2012-0845
=============

Disclosure date: 2012-02-13 (issue #14001 reported).

`CVSS Score`_: 5.0.

A denial of service flaw was found in the way Simple XML-RPC Server module of Python processed client connections, that were closed prior the complete request body has been received. A remote attacker could use this flaw to cause Python Simple XML-RPC based server process to consume excessive amount of CPU.
Reported by Jan Lieskovsky.

Links:

* http://bugs.python.org/issue14001
* http://www.cvedetails.com/cve/CVE-2012-0845/

Fixed In:

* 2.6.8 (57 days): 2012-04-10, `commit 66f3cc6 <https://github.com/python/cpython/commit/66f3cc6f8de83c447d937160e4a1630c4482b5f5>`_ (2012-02-18, 5 days)
* 2.7.3 (56 days): 2012-04-09, `commit 66f3cc6 <https://github.com/python/cpython/commit/66f3cc6f8de83c447d937160e4a1630c4482b5f5>`_ (2012-02-18, 5 days)
* 3.1.5 (55 days): 2012-04-08, `commit ec1712a <https://github.com/python/cpython/commit/ec1712a1662282c909b4cd4cc0c7486646bc9246>`_ (2012-02-18, 5 days)
* 3.2.3 (57 days): 2012-04-10, `commit ec1712a <https://github.com/python/cpython/commit/ec1712a1662282c909b4cd4cc0c7486646bc9246>`_ (2012-02-18, 5 days)
* 3.3.0: 2012-09-29, `commit ec1712a <https://github.com/python/cpython/commit/ec1712a1662282c909b4cd4cc0c7486646bc9246>`_


CVE-2011-3389
=============

Disclosure date: 2012-01-27 (issue #13885 reported).

`CVSS Score`_: 4.3.

The ssl module would always disable the CBC IV attack countermeasure. Disable OpenSSL ``SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS`` option.
Reported by Antoine Pitrou.

Links:

* http://bugs.python.org/issue13885
* http://www.cvedetails.com/cve/CVE-2011-3389/

Fixed In:

* 2.6.8 (74 days): 2012-04-10, `commit d358e05 <https://github.com/python/cpython/commit/d358e0554bc520768041652676ec8e6076f221a9>`_ (2012-01-27, 0 days)
* 2.7.3 (73 days): 2012-04-09, `commit d358e05 <https://github.com/python/cpython/commit/d358e0554bc520768041652676ec8e6076f221a9>`_ (2012-01-27, 0 days)
* 3.1.5 (72 days): 2012-04-08, `commit f2bf8a6 <https://github.com/python/cpython/commit/f2bf8a6ac51530e14d798a03c8e950dd934d85cd>`_ (2012-01-27, 0 days)
* 3.2.3 (74 days): 2012-04-10, `commit f2bf8a6 <https://github.com/python/cpython/commit/f2bf8a6ac51530e14d798a03c8e950dd934d85cd>`_ (2012-01-27, 0 days)
* 3.3.0: 2012-09-29, `commit f2bf8a6 <https://github.com/python/cpython/commit/f2bf8a6ac51530e14d798a03c8e950dd934d85cd>`_


CVE-2012-1150
=============

Disclosure date: 2011-12-28 (CCC talk).

`CVSS Score`_: 5.0.

Hash collision denial of service.
Python 2.6 and 2.7 require the ``-R`` command line option to enable the fix.
"Effective Denial of Service attacks against web application platforms" talk at the CCC: 2011-12-28
See also the `PEP 456: Secure and interchangeable hash algorithm <https://www.python.org/dev/peps/pep-0456/>`_: Python 3.4 switched to `SipHash <https://131002.net/siphash/>`_.

Links:

* http://bugs.python.org/issue13703
* https://events.ccc.de/congress/2011/Fahrplan/events/4680.en.html
* http://www.ocert.org/advisories/ocert-2011-003.html
* http://www.cvedetails.com/cve/CVE-2012-1150/

Fixed In:

* 2.6.8 (104 days): 2012-04-10, `commit 1e13eb0 <https://github.com/python/cpython/commit/1e13eb084f72d5993cbb726e45b36bdb69c83a24>`_ (2012-02-21, 55 days)
* 2.7.3 (103 days): 2012-04-09, `commit 1e13eb0 <https://github.com/python/cpython/commit/1e13eb084f72d5993cbb726e45b36bdb69c83a24>`_ (2012-02-21, 55 days)
* 3.1.5 (102 days): 2012-04-08, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_ (2012-02-20, 54 days)
* 3.2.3 (104 days): 2012-04-10, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_ (2012-02-20, 54 days)
* 3.3.0: 2012-09-29, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_


CVE-2011-4944
=============

Disclosure date: 2011-11-30 (issue #13512 reported).

`CVSS Score`_: 1.9.

Python 2.6 through 3.2 creates ``~/.pypirc`` configuration file with world-readable permissions before changing them after data has been written, which introduces a race condition that allows local users to obtain a username and password by reading this file.

Links:

* http://bugs.python.org/issue13512
* http://www.cvedetails.com/cve/CVE-2011-4944/

Fixed In:

* 2.7.4 (493 days): 2013-04-06, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03, 216 days)
* 3.2.4 (494 days): 2013-04-07, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03, 216 days)
* 3.3.1 (494 days): 2013-04-07, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03, 216 days)
* 3.4.0: 2014-03-16, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_


CVE-2011-1521
=============

Disclosure date: 2011-03-24 (issue #11662 reported).

`CVSS Score`_: 6.4.

The Python urllib and urllib2 modules are typically used to fetch web pages but by default also contains handlers for ``ftp://`` and ``file://`` URL schemes.
Now unfortunately it appears that it is possible for a web server to redirect (HTTP 302) a urllib request to any of the supported schemes.

Links:

* http://bugs.python.org/issue11662
* http://www.cvedetails.com/cve/CVE-2011-1521/

Fixed In:

* 2.5.6 (63 days): 2011-05-26, `commit 60a4a90 <https://github.com/python/cpython/commit/60a4a90c8dd2972eb4bb977e70835be9593cbbac>`_ (2011-03-24, 0 days)
* 2.6.7 (71 days): 2011-06-03, `commit 60a4a90 <https://github.com/python/cpython/commit/60a4a90c8dd2972eb4bb977e70835be9593cbbac>`_ (2011-03-24, 0 days)
* 2.7.2 (79 days): 2011-06-11, `commit 60a4a90 <https://github.com/python/cpython/commit/60a4a90c8dd2972eb4bb977e70835be9593cbbac>`_ (2011-03-24, 0 days)
* 3.1.4 (79 days): 2011-06-11, `commit a119df9 <https://github.com/python/cpython/commit/a119df91f33724f64e6bc1ecb484eeaa30ace014>`_ (2011-03-29, 5 days)
* 3.2.1 (108 days): 2011-07-10, `commit a119df9 <https://github.com/python/cpython/commit/a119df91f33724f64e6bc1ecb484eeaa30ace014>`_ (2011-03-29, 5 days)
* 3.3.0: 2012-09-29, `commit a119df9 <https://github.com/python/cpython/commit/a119df91f33724f64e6bc1ecb484eeaa30ace014>`_


CVE-2011-4940
=============

Disclosure date: 2011-03-08 (issue #11442 reported).

`CVSS Score`_: 2.6.

The list_directory function in Lib/SimpleHTTPServer.py in SimpleHTTPServer in Python before 2.5.6c1, 2.6.x before 2.6.7 rc2, and 2.7.x before 2.7.2 does not place a charset parameter in the Content-Type HTTP header, which makes it easier for remote attackers to conduct cross-site scripting (XSS) attacks against Internet Explorer 7 via UTF-7 encoding.

Links:

* http://bugs.python.org/issue11442
* http://www.cvedetails.com/cve/CVE-2011-4940/

Fixed In:

* 2.5.6 (79 days): 2011-05-26, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 2.6.7 (87 days): 2011-06-03, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 2.7.2 (95 days): 2011-06-11, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 3.2.4 (761 days): 2013-04-07, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 3.3.1 (761 days): 2013-04-07, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 3.4.0: 2014-03-16, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_


Issue #6791
===========

Disclosure date: 2009-08-28 (issue #6791 reported).

Limit the HTTP header readline. Reported by sumar (m.sucajtys).

Links:

* http://bugs.python.org/issue6791

Fixed In:

* 2.7.2 (652 days): 2011-06-11, `commit d7b6ac6 <https://github.com/python/cpython/commit/d7b6ac66c1b81d13f2efa8d9ebba69e17c158c0a>`_ (2010-12-18, 477 days)
* 3.1.4 (652 days): 2011-06-11, `commit ff1bbba <https://github.com/python/cpython/commit/ff1bbba92aad261df1ebd8fd8cc189c104e113b0>`_ (2010-12-18, 477 days)
* 3.2: 2011-02-20, `commit 5466bf1 <https://github.com/python/cpython/commit/5466bf1c94d38e75bc053b0cfc163e2f948fe345>`_


CVE-2011-1015
=============

Disclosure date: 2008-03-07 (issue #2254 reported).

`CVSS Score`_: 5.0.

The ``is_cgi()`` method in ``CGIHTTPServer.py`` in the ``CGIHTTPServer`` module in Python 2.5, 2.6, and 3.0 allows remote attackers to read script source code via an HTTP GET request that lacks a ``/`` (slash) character at the beginning of the URI.

Links:

* http://bugs.python.org/issue2254
* http://www.cvedetails.com/cve/CVE-2011-1015/

Fixed In:

* 2.7 (848 days): 2010-07-03, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06, 395 days)
* 3.2.4 (1857 days): 2013-04-07, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06, 395 days)
* 3.3.1 (1857 days): 2013-04-07, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06, 395 days)
* 3.4.0: 2014-03-16, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_
