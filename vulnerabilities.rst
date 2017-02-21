++++++++++++++++++++++++
Security vulnerabilities
++++++++++++++++++++++++

+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| Vulnerability              | Summary                             | Disclosure   | Score         | Fixed In                                 |
+============================+=====================================+==============+===============+==========================================+
| `Issue #28563`_            | ``gettext.c2py()``                  | 2016-10-30   | ?             | 2.7.13, 3.4.6, 3.5.3, 3.6.0              |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-2183`_           | Sweet32 attack (DES, 3DES)          | 2016-08-24   | 5.0           | 2.7.13, 3.5.3, 3.6.0                     |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-1000110`_        | HTTPoxy attack                      | 2016-07-18   | 5.0 (CVSS v3) | 2.7.13, 3.4.6, 3.5.3, 3.6.0              |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-0772`_           | smtplib TLS stripping               | 2016-06-11   | 5.8           | 2.7.12, 3.4.5, 3.5.2, 3.6.0              |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `Issue #26657`_            | HTTP directory traversal            | 2016-03-28   | ?             | 2.7.12, 3.5.2, 3.6.0                     |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-5636`_           | zipimporter heap overflow           | 2016-01-21   | 10.0          | 2.7.12, 3.4.5, 3.5.2, 3.6.0              |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2015-1283`_           | expat 2.1.1                         | 2015-07-24   | 6.8           | 2.7.12, 3.4.5, 3.5.2, 3.6.0              |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2016-5699`_           | HTTP header injection               | 2014-11-24   | 4.3           | 2.7.10, 3.4.4, 3.5.0                     |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-7185`_           | buffer integer overflow             | 2014-06-24   | 6.4           | 2.7.8                                    |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-9365`_           | Validate TLS certificate            | 2014-04-19   | 5.8           | 2.7.9, 3.4.3, 3.5.0                      |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-4616`_           | JSON arbitrary memory access        | 2014-04-13   | Moderate      | 2.7.7, 3.2.6, 3.3.6, 3.4.1, 3.5.0        |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-2667`_           | ``os.makedirs()`` not thread-safe   | 2014-03-28   | 3.3           | 3.2.6, 3.3.6, 3.4.1, 3.5.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2014-1912`_           | ``socket.recvfrom_into()`` overflow | 2014-01-14   | 7.5           | 2.7.7, 3.2.6, 3.3.4, 3.4.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-7338`_           | zipfile DoS using malformed file    | 2013-12-27   | 7.1           | 3.3.4, 3.4.0                             |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `Issue #19435`_            | CGI directory traversal             | 2013-10-29   | ?             | 2.7.6, 3.2.6, 3.3.4, 3.4.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-4238`_           | ssl: NUL in subjectAltNames         | 2013-08-12   | 4.3           | 2.6.9, 2.7.6, 3.3.3, 3.4.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-7440`_           | ``ssl.match_hostname()`` IDNA issue | 2013-05-17   | 4.3           | 3.3.3, 3.4.0                             |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-2099`_           | ``ssl.match_hostname()`` wildcard   | 2013-05-15   | 4.3           | 3.3.3, 3.4.0                             |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (ftplib)`_  | ftplib unlimited read               | 2012-09-25   | Moderate      | 2.7.6, 3.2.6, 3.3.3, 3.4.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (nntplib)`_ | nntplib unlimited read              | 2012-09-25   | Moderate      | 2.6.9, 2.7.6, 3.2.6, 3.4.3, 3.5.0        |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (poplib)`_  | poplib unlimited read               | 2012-09-25   | Moderate      | 2.7.9, 3.2.6, 3.4.3, 3.5.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1752 (smtplib)`_ | smtplib unlimited read              | 2012-09-25   | Moderate      | 2.7.9, 3.2.6, 3.4.3, 3.5.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-1753`_           | xmlrpc unlimited read               | 2012-09-25   | Moderate      | 2.7.9, 3.4.3, 3.5.0                      |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2013-7040`_           | Hash not randomized properly        | 2012-04-19   | 4.3           | 3.4.0                                    |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2012-2135`_           | UTF-16 decoder                      | 2012-04-14   | 6.4           | 2.7.4, 3.2.4, 3.3.0                      |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2012-0845`_           | XML-RPC DoS                         | 2012-02-13   | 5.0           | 2.6.8, 2.7.3, 3.1.5, 3.2.3, 3.3.0        |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-3389`_           | ssl CBC IV attack                   | 2012-01-27   | 4.3           | 2.6.8, 2.7.3, 3.1.5, 3.2.3, 3.3.0        |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2012-1150`_           | Hash collision denial of service    | 2011-12-28   | 5.0           | 2.6.8, 2.7.3, 3.1.5, 3.2.3, 3.3.0        |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-4944`_           | ``~/.pypirc`` created insecurely    | 2011-11-30   | 1.9           | 2.7.4, 3.2.4, 3.3.1, 3.4.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-1521`_           | urllib redirect vulnerability       | 2011-03-24   | 6.4           | 2.5.6, 2.6.7, 2.7.2, 3.1.4, 3.2.1, 3.3.0 |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-4940`_           | SimpleHTTPServer UTF-7              | 2011-03-08   | 2.6           | 2.5.6, 2.6.7, 2.7.2, 3.2.4, 3.3.1, 3.4.0 |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2010-1634`_           | audioop integer overflows           | 2010-05-10   | 5.0           | 2.6.6, 2.7, 3.1.3, 3.2                   |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2010-2089`_           | audioop input validation            | 2010-01-11   | 5.0           | 2.6.6, 2.7.2, 3.1.3, 3.2                 |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `Issue #6791`_             | httplib unlimited read              | 2009-08-28   | ?             | 2.7.2, 3.1.4, 3.2                        |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2010-3492`_           | smtpd accept bug                    | 2009-08-14   | 5.0           | 2.7.4, 3.2                               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2010-3493`_           | smtpd race conditions               | 2009-08-14   | 4.3           | 2.7.1, 3.1.3, 3.2.1, 3.3.0               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2008-2315`_           | Multiple integer overflows          | 2008-07-31   | 7.5           | 2.6.0, 3.0.0                             |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2008-3143`_           | multiple integer overflows          | 2008-04-11   | 7.5           | 2.5.3, 2.6, 3.0                          |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2008-5031`_           | ``expandtab()`` integer overflow    | 2008-03-11   | 10.0          | 2.5.3, 2.6, 3.0                          |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2011-1015`_           | CGI directory traversal             | 2008-03-07   | 5.0           | 2.7, 3.2.4, 3.3.1, 3.4.0                 |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+
| `CVE-2007-4965`_           | rgbimg and imageop overflows        | 2007-09-16   | 5.8           | 2.5.3, 2.6                               |
+----------------------------+-------------------------------------+--------------+---------------+------------------------------------------+

Total: 41 vulnerabilities

* Vulnerabilities sorted by the Disclosure column
* Disclosure: Disclosure date, first time that the vulnerability was public
* `CVSS Score <https://nvd.nist.gov/cvss.cfm>`_
* `Red Hat impact <https://access.redhat.com/security/updates/classification/>`_


Issue #28563
============

Arbitrary code execution in ``gettext.c2py()``.

Information:

* Disclosure date: 2016-10-30 (issue #28563 reported).

Links:

* http://bugs.python.org/issue28563

Fixed In:

* 2.7.13 (48 days): 2016-12-17, `commit a876027 <https://github.com/python/cpython/commit/a8760275bd59fb8d8be1f1bf05313fed31c08321>`_ (2016-11-08, 9 days)
* 3.4.6 (79 days): 2017-01-17, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08, 9 days)
* 3.5.3 (79 days): 2017-01-17, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08, 9 days)
* 3.6.0: 2016-12-23, `commit 07bcf05 <https://github.com/python/cpython/commit/07bcf05fcf3fd1d4001e8e3489162e6d67638285>`_ (2016-11-08)


CVE-2016-2183
=============

Remove 3DES from ssl default cipher list.

Sweet32 vulnerability found by Karthik Bhargavan and Gaetan Leurent from
the `INRIA <https://www.inria.fr/>`_.

Information:

* Disclosure date: 2016-08-24 (issue #27850 reported).
* Reported by: Karthik Bhargavan and Gaetan Leurent.
* `CVSS Score`_: 5.0.

Links:

* http://bugs.python.org/issue27850
* https://sweet32.info/
* https://www.openssl.org/blog/blog/2016/08/24/sweet32/
* http://www.cvedetails.com/cve/CVE-2016-2183/

Fixed In:

* 2.7.13 (115 days): 2016-12-17, `commit d988f42 <https://github.com/python/cpython/commit/d988f429fe43808345812ef63dfa8da170c61871>`_ (2016-09-06, 13 days)
* 3.5.3 (146 days): 2017-01-17, `commit 03d13c0 <https://github.com/python/cpython/commit/03d13c0cbfe912eb0f9b9a02987b9e569f25fe19>`_ (2016-09-06, 13 days)
* 3.6.0: 2016-12-23, `commit 03d13c0 <https://github.com/python/cpython/commit/03d13c0cbfe912eb0f9b9a02987b9e569f25fe19>`_ (2016-09-06)


CVE-2016-1000110
================

Prevent HTTPoxy attack.

Ignore the HTTP_PROXY variable when REQUEST_METHOD environment is set, which
indicates that the script is in CGI mode.

Information:

* Disclosure date: 2016-07-18 (issue #27568 reported).
* Reported by: Rémi Rampin.
* `CVSS Score`_: 5.0 (CVSS v3).

Links:

* http://bugs.python.org/issue27568
* https://httpoxy.org/
* https://access.redhat.com/security/cve/cve-2016-1000110
* http://www.cvedetails.com/cve/CVE-2016-1000110/

Fixed In:

* 2.7.13 (152 days): 2016-12-17, `commit 75d7b61 <https://github.com/python/cpython/commit/75d7b615ba70fc5759d16dee95bbd8f0474d8a9c>`_ (2016-07-30, 12 days)
* 3.4.6 (183 days): 2017-01-17, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-31, 13 days)
* 3.5.3 (183 days): 2017-01-17, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-31, 13 days)
* 3.6.0: 2016-12-23, `commit 4cbb23f <https://github.com/python/cpython/commit/4cbb23f8f278fd1f71dcd5968aa0b3f0b4f3bd5d>`_ (2016-07-31)


CVE-2016-0772
=============

A vulnerability in smtplib allowing MITM attacker to perform a startTLS
stripping attack. smtplib does not seem to raise an exception when the
remote end (SMTP server) is capable of negotiating starttls but fails to
respond with 220 (ok) to an explicit call of SMTP.starttls(). This may
allow a malicious MITM to perform a startTLS stripping attack if the client
code does not explicitly check the response code for startTLS.

Information:

* Disclosure date: 2016-06-11 (commit date).
* Reported by: Tin (Team Oststrom).
* `CVSS Score`_: 5.8.

Links:

* http://seclists.org/oss-sec/2016/q2/541
* https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-0772
* http://www.cvedetails.com/cve/CVE-2016-0772/

Fixed In:

* 2.7.12 (17 days): 2016-06-28, `commit 2e1b7fc <https://github.com/python/cpython/commit/2e1b7fc998e1744eeb3bb31b131eba0145b88a2f>`_ (2016-06-11, 0 days)
* 3.4.5 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11, 0 days)
* 3.5.2 (16 days): 2016-06-27, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11, 0 days)
* 3.6.0: 2016-12-23, `commit 46b32f3 <https://github.com/python/cpython/commit/46b32f307c48bcb999b22eebf65ffe8ed5cca544>`_ (2016-06-11)


Issue #26657
============

Fix directory traversal vulnerability with ``http.server`` and
``SimpleHTTPServer`` on Windows.

Regression of Python 3.3.5.

Information:

* Disclosure date: 2016-03-28 (issue #26657 reported).

Links:

* http://bugs.python.org/issue26657

Fixed In:

* 2.7.12 (92 days): 2016-06-28, `commit 0cf2cf2 <https://github.com/python/cpython/commit/0cf2cf2b7d726d12a6046441e4067d32c7dd4feb>`_ (2016-04-18, 21 days)
* 3.5.2 (91 days): 2016-06-27, `commit d274b3f <https://github.com/python/cpython/commit/d274b3f1f1e2d8811733fb952c9f18d7da3a376a>`_ (2016-04-18, 21 days)
* 3.6.0: 2016-12-23, `commit d274b3f <https://github.com/python/cpython/commit/d274b3f1f1e2d8811733fb952c9f18d7da3a376a>`_ (2016-04-18)


CVE-2016-5636
=============

Heap overflow in ``zipimporter`` module.

Information:

* Disclosure date: 2016-01-21 (issue #26171 reported).
* `CVSS Score`_: 10.0.

Links:

* https://bugs.python.org/issue26171
* http://www.cvedetails.com/cve/CVE-2016-5636/

Fixed In:

* 2.7.12 (159 days): 2016-06-28, `commit 64ea192 <https://github.com/python/cpython/commit/64ea192b73e39e877d8b39ce6584fa580eb0e9b4>`_ (2016-01-21, 0 days)
* 3.4.5 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-21, 0 days)
* 3.5.2 (158 days): 2016-06-27, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-21, 0 days)
* 3.6.0: 2016-12-23, `commit c4032da <https://github.com/python/cpython/commit/c4032da2012d75c6c358f74d8bf9ee98a7fe8ecf>`_ (2016-01-21)


CVE-2015-1283
=============

Multiple integer overflows have been discovered in Expat, an XML parsing C
library, which may result in denial of service or the execution of
arbitrary code if a malformed XML file is processed.

Update Expat to 2.1.1.

Information:

* Disclosure date: 2015-07-24 (expat issue reported).
* `CVSS Score`_: 6.8.

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
* 3.6.0: 2016-12-23, `commit 196d7db <https://github.com/python/cpython/commit/196d7db3956f4c0b03e87b570771b3460a61bab5>`_ (2016-06-11)


CVE-2016-5699
=============

HTTP header injection in ``urllib``, ``urrlib2``, ``httplib`` and
``http.client`` modules.

CRLF injection vulnerability in the ``HTTPConnection.putheader()`` function
in ``urllib2`` and ``urllib`` in CPython before 2.7.10 and 3.x before 3.4.4
allows remote attackers to inject arbitrary HTTP headers via CRLF sequences
in a URL.

Information:

* Disclosure date: 2014-11-24 (issue #22928 reported).
* `CVSS Score`_: 4.3.

Links:

* https://bugs.python.org/issue22928
* https://access.redhat.com/security/cve/cve-2014-4616
* http://www.cvedetails.com/cve/CVE-2016-5699/

Fixed In:

* 2.7.10 (180 days): 2015-05-23, `commit 59bdf63 <https://github.com/python/cpython/commit/59bdf6392de446de8a19bfa37cee52981612830e>`_ (2015-03-12, 108 days)
* 3.4.4 (392 days): 2015-12-21, `commit a112a8a <https://github.com/python/cpython/commit/a112a8ae47813f75aa8ad27ee8c42a7c2e937d13>`_ (2015-03-12, 108 days)
* 3.5.0: 2015-09-09, `commit a112a8a <https://github.com/python/cpython/commit/a112a8ae47813f75aa8ad27ee8c42a7c2e937d13>`_ (2015-03-12)


CVE-2014-7185
=============

Integer overflow in ``bufferobject.c`` in Python before 2.7.8 allows
context-dependent attackers to obtain sensitive information from process
memory via a large size and offset in a ``buffer`` type.

Information:

* Disclosure date: 2014-06-24 (issue #21831 reported).
* Reported by: Chris Foster (on the Python security list).
* `CVSS Score`_: 6.4.

Links:

* http://bugs.python.org/issue21831
* http://www.cvedetails.com/cve/CVE-2014-7185/

Fixed In:

* 2.7.8 (5 days): 2014-06-29, `commit 550b945 <https://github.com/python/cpython/commit/550b945fd66f1c6837a53fbf29dc8e524297b8c3>`_ (2014-06-24, 0 days)


CVE-2014-9365
=============

Python 2.7 backport of many ssl features from Python 3.

A contribution of Alex Gaynor and David Reid with the generous support of
Rackspace. May God have mercy on their souls.

Information:

* Disclosure date: 2014-04-19 (issue #21308 reported).
* `CVSS Score`_: 5.8.

Links:

* http://bugs.python.org/issue21308
* http://bugs.python.org/issue22417
* https://www.python.org/dev/peps/pep-0466/
* https://www.python.org/dev/peps/pep-0476/
* http://www.cvedetails.com/cve/CVE-2014-9365/

Fixed In:

* 2.7.9 (235 days): 2014-12-10, `commit daeb925 <https://github.com/python/cpython/commit/daeb925cc88cc8fed2030166ade641de28edb396>`_ (2014-08-20, 123 days)
* 3.4.3 (310 days): 2015-02-23, `commit 4ffb075 <https://github.com/python/cpython/commit/4ffb0752710f0c0720d4f2af0c4b7ce1ebb9d2bd>`_ (2014-11-03, 198 days)
* 3.5.0: 2015-09-09, `commit 4ffb075 <https://github.com/python/cpython/commit/4ffb0752710f0c0720d4f2af0c4b7ce1ebb9d2bd>`_ (2014-11-03)


CVE-2014-4616
=============

Fix arbitrary memory access in ``JSONDecoder.raw_decode`` with a negative
second parameter.

Information:

* Disclosure date: 2014-04-13 (commit).
* Reported by: Guido Vranken.
* `Red Hat impact`_: Moderate.

Links:

* http://bugs.python.org/issue21529
* http://www.cvedetails.com/cve/CVE-2014-4616/

Fixed In:

* 2.7.7 (48 days): 2014-05-31, `commit 6c939cb <https://github.com/python/cpython/commit/6c939cb6f6dfbd273609577b0022542d31ae2802>`_ (2014-04-14, 1 days)
* 3.2.6 (181 days): 2014-10-11, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14, 1 days)
* 3.3.6 (181 days): 2014-10-11, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14, 1 days)
* 3.4.1 (35 days): 2014-05-18, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14, 1 days)
* 3.5.0: 2015-09-09, `commit 99b5afa <https://github.com/python/cpython/commit/99b5afab74428e5ddfd877bdf3aa8a8c479696b1>`_ (2014-04-14)


CVE-2014-2667
=============

``os.makedirs(exist_ok=True)`` is not thread-safe: umask is set temporary
to ``0``, serious security problem.

Remove directory mode check from ``os.makedirs()``.

Information:

* Disclosure date: 2014-03-28 (issue #21082 reported).
* Reported by: Ryan Lortie.
* `CVSS Score`_: 3.3.

Links:

* http://bugs.python.org/issue21082
* http://www.cvedetails.com/cve/CVE-2014-2667/

Fixed In:

* 3.2.6 (197 days): 2014-10-11, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01, 4 days)
* 3.3.6 (197 days): 2014-10-11, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01, 4 days)
* 3.4.1 (51 days): 2014-05-18, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01, 4 days)
* 3.5.0: 2015-09-09, `commit ee5f1c1 <https://github.com/python/cpython/commit/ee5f1c13d1ea21c628068fdf142823177f5526c2>`_ (2014-04-01)


CVE-2014-1912
=============

``socket.recvfrom_into()`` fails to check that the supplied buffer object
is big enough for the requested read and so will happily write off the end.

Information:

* Disclosure date: 2014-01-14 (issue #20246 reported).
* Reported by: Ryan Smith-Roberts.
* `CVSS Score`_: 7.5.

Links:

* http://bugs.python.org/issue20246
* http://www.cvedetails.com/cve/CVE-2014-1912/

Fixed In:

* 2.7.7 (137 days): 2014-05-31, `commit 28cf368 <https://github.com/python/cpython/commit/28cf368c1baba3db1f01010e921f63017af74c8f>`_ (2014-01-14, 0 days)
* 3.2.6 (270 days): 2014-10-11, `commit fbf648e <https://github.com/python/cpython/commit/fbf648ebba32bbc5aa571a4b09e2062a65fd2492>`_ (2014-01-14, 0 days)
* 3.3.4 (26 days): 2014-02-09, `commit fbf648e <https://github.com/python/cpython/commit/fbf648ebba32bbc5aa571a4b09e2062a65fd2492>`_ (2014-01-14, 0 days)
* 3.4.0: 2014-03-16, `commit fbf648e <https://github.com/python/cpython/commit/fbf648ebba32bbc5aa571a4b09e2062a65fd2492>`_ (2014-01-14)


CVE-2013-7338
=============

Python before 3.3.4 RC1 allows remote attackers to cause a denial of
service (infinite loop and CPU consumption) via a file size value larger
than the size of the zip file to the functions:

* ``ZipExtFile.read()``
* ``ZipExtFile.readlines()``
* ``ZipFile.extract()``
* ``ZipFile.extractall()``

Reading malformed zipfiles no longer hangs with 100% CPU consumption.

Python 2.7 is not affected.

Information:

* Disclosure date: 2013-12-27 (issue #20078 reported).
* Reported by: Nandiya.
* `CVSS Score`_: 7.1.

Links:

* http://bugs.python.org/issue20078
* http://www.cvedetails.com/cve/CVE-2013-7338/

Fixed In:

* 3.3.4 (44 days): 2014-02-09, `commit 5ce3f10 <https://github.com/python/cpython/commit/5ce3f10aeea711bb912e948fa5d9f63736df1327>`_ (2014-01-09, 13 days)
* 3.4.0: 2014-03-16, `commit 5ce3f10 <https://github.com/python/cpython/commit/5ce3f10aeea711bb912e948fa5d9f63736df1327>`_ (2014-01-09)


Issue #19435
============

An error in separating the path and filename of the CGI script to run in
``http.server.CGIHTTPRequestHandler`` allows running arbitrary executables in
the directory under which the server was started.

Information:

* Disclosure date: 2013-10-29 (issue #19435 reported).
* Reported by: Alexander Kruppa.

Links:

* http://bugs.python.org/issue19435

Fixed In:

* 2.7.6 (12 days): 2013-11-10, `commit 1ef959a <https://github.com/python/cpython/commit/1ef959ac3ddc4d96dfa1a613db5cb206cdaeb662>`_ (2013-10-30, 1 days)
* 3.2.6 (347 days): 2014-10-11, `commit 04e9de4 <https://github.com/python/cpython/commit/04e9de40f380b2695f955d68f2721d57cecbf858>`_ (2013-10-30, 1 days)
* 3.3.4 (103 days): 2014-02-09, `commit 04e9de4 <https://github.com/python/cpython/commit/04e9de40f380b2695f955d68f2721d57cecbf858>`_ (2013-10-30, 1 days)
* 3.4.0: 2014-03-16, `commit 04e9de4 <https://github.com/python/cpython/commit/04e9de40f380b2695f955d68f2721d57cecbf858>`_ (2013-10-30)


CVE-2013-4238
=============

SSL module fails to handle NULL bytes inside subjectAltNames general names.

Information:

* Disclosure date: 2013-08-12 (issue #18709 reported).
* Reported by: Christian Heimes.
* `CVSS Score`_: 4.3.

Links:

* http://bugs.python.org/issue18709
* http://www.cvedetails.com/cve/CVE-2013-4238/

Fixed In:

* 2.6.9 (78 days): 2013-10-29, `commit 82f8828 <https://github.com/python/cpython/commit/82f88283171933127f20f866a7f98694b29cca56>`_ (2013-08-23, 11 days)
* 2.7.6 (90 days): 2013-11-10, `commit 82f8828 <https://github.com/python/cpython/commit/82f88283171933127f20f866a7f98694b29cca56>`_ (2013-08-23, 11 days)
* 3.3.3 (97 days): 2013-11-17, `commit 824f7f3 <https://github.com/python/cpython/commit/824f7f366d1b54d2d3100c3130c04cf1dfb4b47c>`_ (2013-08-16, 4 days)
* 3.4.0: 2014-03-16, `commit 824f7f3 <https://github.com/python/cpython/commit/824f7f366d1b54d2d3100c3130c04cf1dfb4b47c>`_ (2013-08-16)


CVE-2013-7440
=============

``ssl.match_hostname()``: sub string wildcard should not match IDNA prefix.

Change behavior of ``ssl.match_hostname()`` to follow RFC 6125, for
security reasons.  It now doesn't match multiple wildcards nor wildcards
inside IDN fragments.

Information:

* Disclosure date: 2013-05-17 (issue #17997 reported).
* Reported by: Christian Heimes.
* `CVSS Score`_: 4.3.

Links:

* https://bugs.python.org/issue17997
* https://tools.ietf.org/html/rfc6125
* http://www.cvedetails.com/cve/CVE-2013-7440/

Fixed In:

* 3.3.3 (184 days): 2013-11-17, `commit 72c98d3 <https://github.com/python/cpython/commit/72c98d3a761457a4f2b8054458b19f051dfb5886>`_ (2013-10-27, 163 days)
* 3.4.0: 2014-03-16, `commit 72c98d3 <https://github.com/python/cpython/commit/72c98d3a761457a4f2b8054458b19f051dfb5886>`_ (2013-10-27)


CVE-2013-2099
=============

If the name in the certificate contains many ``*`` characters (wildcard),
matching the compiled regular expression against the host name can take a
very long time.

Certificate validation happens before host name checking, so I think this
is a minor issue only because it can only be triggered in cooperation with
a CA (which seems unlikely).

Information:

* Disclosure date: 2013-05-15 (issue #17980 reported).
* Reported by: Florian Weimer.
* `CVSS Score`_: 4.3.

Links:

* http://bugs.python.org/issue17980
* http://www.cvedetails.com/cve/CVE-2013-2099/

Fixed In:

* 3.3.3 (186 days): 2013-11-17, `commit 636f93c <https://github.com/python/cpython/commit/636f93c63ba286249c1207e3a903f8429efb2041>`_ (2013-05-18, 3 days)
* 3.4.0: 2014-03-16, `commit 636f93c <https://github.com/python/cpython/commit/636f93c63ba286249c1207e3a903f8429efb2041>`_ (2013-05-18)


CVE-2013-1752 (ftplib)
======================

ftplib: unlimited read from connection.

Information:

* Disclosure date: 2012-09-25 (issue #16038 reported).
* Reported by: Christian Heimes.
* `Red Hat impact`_: Moderate.

Links:

* http://bugs.python.org/issue16038
* https://access.redhat.com/security/cve/cve-2013-1752
* http://www.cvedetails.com/cve/CVE-2013-1752/

Fixed In:

* 2.7.6 (411 days): 2013-11-10, `commit 2585e1e <https://github.com/python/cpython/commit/2585e1e48abb3013abeb8a1fe9dccb5f79ac4091>`_ (2013-10-20, 390 days)
* 3.2.6 (746 days): 2014-10-11, `commit c9cb18d <https://github.com/python/cpython/commit/c9cb18d3f7e5bf03220c213183ff0caa75905bdd>`_ (2014-09-30, 735 days)
* 3.3.3 (418 days): 2013-11-17, `commit c30b178 <https://github.com/python/cpython/commit/c30b178cbc92e62c22527cd7e1af2f02723ba679>`_ (2013-10-20, 390 days)
* 3.4.0: 2014-03-16, `commit c30b178 <https://github.com/python/cpython/commit/c30b178cbc92e62c22527cd7e1af2f02723ba679>`_ (2013-10-20)


CVE-2013-1752 (nntplib)
=======================

Unlimited read from connection in nntplib.

Information:

* Disclosure date: 2012-09-25 (issue #16040 reported).
* `Red Hat impact`_: Moderate.

Links:

* http://bugs.python.org/issue16040
* https://access.redhat.com/security/cve/cve-2013-1752
* http://www.cvedetails.com/cve/CVE-2013-1752/

Fixed In:

* 2.6.9 (399 days): 2013-10-29, `commit 42faa55 <https://github.com/python/cpython/commit/42faa55124abcbb132c57745dec9e0489ac74406>`_ (2013-09-30, 370 days)
* 2.7.6 (411 days): 2013-11-10, `commit 42faa55 <https://github.com/python/cpython/commit/42faa55124abcbb132c57745dec9e0489ac74406>`_ (2013-09-30, 370 days)
* 3.2.6 (746 days): 2014-10-11, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12, 747 days)
* 3.4.3 (881 days): 2015-02-23, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12, 747 days)
* 3.5.0: 2015-09-09, `commit b3ac843 <https://github.com/python/cpython/commit/b3ac84322fe6dd542aa755779cdbc155edca8064>`_ (2014-10-12)


CVE-2013-1752 (poplib)
======================

poplib: unlimited read from connection.

Information:

* Disclosure date: 2012-09-25 (iIssue #16041 reported).
* `Red Hat impact`_: Moderate.

Links:

* http://bugs.python.org/issue16041
* https://access.redhat.com/security/cve/cve-2013-1752
* http://www.cvedetails.com/cve/CVE-2013-1752/

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit faad6bb <https://github.com/python/cpython/commit/faad6bbea6c86e30c770eb0a3648e2cd52b2e55e>`_ (2014-12-06, 802 days)
* 3.2.6 (746 days): 2014-10-11, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30, 735 days)
* 3.4.3 (881 days): 2015-02-23, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30, 735 days)
* 3.5.0: 2015-09-09, `commit eaca861 <https://github.com/python/cpython/commit/eaca8616ab0e219ebb5cf37d495f4bf336ec0f5e>`_ (2014-09-30)


CVE-2013-1752 (smtplib)
=======================

CVE-2013-1752: The smtplib module doesn't limit the amount of read data in
its call to readline(). An erroneous or malicious SMTP server can trick the
smtplib module to consume large amounts of memory.

Information:

* Disclosure date: 2012-09-25 (issue #16042 reported).
* `Red Hat impact`_: Moderate.

Links:

* http://bugs.python.org/issue16042
* https://access.redhat.com/security/cve/cve-2013-1752
* http://www.cvedetails.com/cve/CVE-2013-1752/

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit dabfc56 <https://github.com/python/cpython/commit/dabfc56b57f5086eb5522d8e6cd7670c62d2482d>`_ (2014-12-06, 802 days)
* 3.2.6 (746 days): 2014-10-11, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30, 735 days)
* 3.4.3 (881 days): 2015-02-23, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30, 735 days)
* 3.5.0: 2015-09-09, `commit 210ee47 <https://github.com/python/cpython/commit/210ee47e3340d8e689d8cce584e7c918d368f16b>`_ (2014-09-30)


CVE-2013-1753
=============

Add a default limit for the amount of data ``xmlrpclib.gzip_decode()`` will
return.

Information:

* Disclosure date: 2012-09-25 (issue #16043 reported).
* `Red Hat impact`_: Moderate.

Links:

* http://bugs.python.org/issue16043
* https://access.redhat.com/security/cve/cve-2013-1753
* http://www.cvedetails.com/cve/CVE-2013-1753/

Fixed In:

* 2.7.9 (806 days): 2014-12-10, `commit 9e8f523 <https://github.com/python/cpython/commit/9e8f523c5b1c354097753084054eadf14d33238d>`_ (2014-12-06, 802 days)
* 3.4.3 (881 days): 2015-02-23, `commit 4e9cefa <https://github.com/python/cpython/commit/4e9cefaf86035f8014e09049328d197b6506532f>`_ (2014-12-06, 802 days)
* 3.5.0: 2015-09-09, `commit 4e9cefa <https://github.com/python/cpython/commit/4e9cefaf86035f8014e09049328d197b6506532f>`_ (2014-12-06)


CVE-2013-7040
=============

Hash function is not randomized properly.

Python 3.4 now used SipHash (PEP 456).

Python 3.3 and Python 2.7 are still affected.

Information:

* Disclosure date: 2012-04-19 (issue #14621 reported).
* Reported by: Vlado Boza.
* `CVSS Score`_: 4.3.

Links:

* http://bugs.python.org/issue14621
* http://www.cvedetails.com/cve/CVE-2013-7040/

Fixed In:

* 3.4.0 (696 days): 2014-03-16, `commit 985ecdc <https://github.com/python/cpython/commit/985ecdcfc29adfc36ce2339acf03f819ad414869>`_ (2013-11-20, 580 days)


CVE-2012-2135
=============

Vulnerability in the UTF-16 decoder after error handling.

Information:

* Disclosure date: 2012-04-14.
* Reported by: Serhiy Storchaka.
* `CVSS Score`_: 6.4.

Links:

* http://bugs.python.org/issue14579
* http://www.cvedetails.com/cve/CVE-2012-2135/

Fixed In:

* 2.7.4 (357 days): 2013-04-06, `commit 715a63b <https://github.com/python/cpython/commit/715a63b78349952ccc0fb3dd3139e2d822006d35>`_ (2012-07-20, 97 days)
* 3.2.4 (358 days): 2013-04-07, `commit 715a63b <https://github.com/python/cpython/commit/715a63b78349952ccc0fb3dd3139e2d822006d35>`_ (2012-07-20, 97 days)
* 3.3.0: 2012-09-29, `commit b4bbee2 <https://github.com/python/cpython/commit/b4bbee25b1e3f4bccac222f806b3138fb72439d6>`_ (2012-07-20)


CVE-2012-0845
=============

A denial of service flaw was found in the way Simple XML-RPC Server module
of Python processed client connections, that were closed prior the complete
request body has been received. A remote attacker could use this flaw to
cause Python Simple XML-RPC based server process to consume excessive
amount of CPU.

Information:

* Disclosure date: 2012-02-13 (issue #14001 reported).
* Reported by: Jan Lieskovsky.
* `CVSS Score`_: 5.0.

Links:

* http://bugs.python.org/issue14001
* http://www.cvedetails.com/cve/CVE-2012-0845/

Fixed In:

* 2.6.8 (57 days): 2012-04-10, `commit 66f3cc6 <https://github.com/python/cpython/commit/66f3cc6f8de83c447d937160e4a1630c4482b5f5>`_ (2012-02-18, 5 days)
* 2.7.3 (56 days): 2012-04-09, `commit 66f3cc6 <https://github.com/python/cpython/commit/66f3cc6f8de83c447d937160e4a1630c4482b5f5>`_ (2012-02-18, 5 days)
* 3.1.5 (55 days): 2012-04-08, `commit ec1712a <https://github.com/python/cpython/commit/ec1712a1662282c909b4cd4cc0c7486646bc9246>`_ (2012-02-18, 5 days)
* 3.2.3 (57 days): 2012-04-10, `commit ec1712a <https://github.com/python/cpython/commit/ec1712a1662282c909b4cd4cc0c7486646bc9246>`_ (2012-02-18, 5 days)
* 3.3.0: 2012-09-29, `commit ec1712a <https://github.com/python/cpython/commit/ec1712a1662282c909b4cd4cc0c7486646bc9246>`_ (2012-02-18)


CVE-2011-3389
=============

The ssl module would always disable the CBC IV attack countermeasure.
Disable OpenSSL ``SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS`` option.

Information:

* Disclosure date: 2012-01-27 (issue #13885 reported).
* Reported by: Antoine Pitrou.
* `CVSS Score`_: 4.3.

Links:

* http://bugs.python.org/issue13885
* http://www.cvedetails.com/cve/CVE-2011-3389/

Fixed In:

* 2.6.8 (74 days): 2012-04-10, `commit d358e05 <https://github.com/python/cpython/commit/d358e0554bc520768041652676ec8e6076f221a9>`_ (2012-01-27, 0 days)
* 2.7.3 (73 days): 2012-04-09, `commit d358e05 <https://github.com/python/cpython/commit/d358e0554bc520768041652676ec8e6076f221a9>`_ (2012-01-27, 0 days)
* 3.1.5 (72 days): 2012-04-08, `commit f2bf8a6 <https://github.com/python/cpython/commit/f2bf8a6ac51530e14d798a03c8e950dd934d85cd>`_ (2012-01-27, 0 days)
* 3.2.3 (74 days): 2012-04-10, `commit f2bf8a6 <https://github.com/python/cpython/commit/f2bf8a6ac51530e14d798a03c8e950dd934d85cd>`_ (2012-01-27, 0 days)
* 3.3.0: 2012-09-29, `commit f2bf8a6 <https://github.com/python/cpython/commit/f2bf8a6ac51530e14d798a03c8e950dd934d85cd>`_ (2012-01-27)


CVE-2012-1150
=============

Hash collision denial of service.

Python 2.6 and 2.7 require the ``-R`` command line option to enable the
fix.

"Effective Denial of Service attacks against web application platforms"
talk at the CCC: 2011-12-28

See also the `PEP 456: Secure and interchangeable hash algorithm
<https://www.python.org/dev/peps/pep-0456/>`_: Python 3.4 switched to
`SipHash <https://131002.net/siphash/>`_.

Information:

* Disclosure date: 2011-12-28 (CCC talk).
* `CVSS Score`_: 5.0.

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
* 3.3.0: 2012-09-29, `commit 2daf6ae <https://github.com/python/cpython/commit/2daf6ae2495c862adf8bc717bfe9964081ea0b10>`_ (2012-02-20)


CVE-2011-4944
=============

Python 2.6 through 3.2 creates ``~/.pypirc`` configuration file with
world-readable permissions before changing them after data has been
written, which introduces a race condition that allows local users to
obtain a username and password by reading this file.

Information:

* Disclosure date: 2011-11-30 (issue #13512 reported).
* `CVSS Score`_: 1.9.

Links:

* http://bugs.python.org/issue13512
* http://www.cvedetails.com/cve/CVE-2011-4944/

Fixed In:

* 2.7.4 (493 days): 2013-04-06, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03, 216 days)
* 3.2.4 (494 days): 2013-04-07, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03, 216 days)
* 3.3.1 (494 days): 2013-04-07, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03, 216 days)
* 3.4.0: 2014-03-16, `commit e5567cc <https://github.com/python/cpython/commit/e5567ccc863cadb68f5e57a2760e021e0d3807cf>`_ (2012-07-03)


CVE-2011-1521
=============

The Python urllib and urllib2 modules are typically used to fetch web pages
but by default also contains handlers for ``ftp://`` and ``file://`` URL
schemes.

Now unfortunately it appears that it is possible for a web server to
redirect (HTTP 302) a urllib request to any of the supported schemes.

Information:

* Disclosure date: 2011-03-24 (issue #11662 reported).
* `CVSS Score`_: 6.4.

Links:

* http://bugs.python.org/issue11662
* http://www.cvedetails.com/cve/CVE-2011-1521/

Fixed In:

* 2.5.6 (63 days): 2011-05-26, `commit 60a4a90 <https://github.com/python/cpython/commit/60a4a90c8dd2972eb4bb977e70835be9593cbbac>`_ (2011-03-24, 0 days)
* 2.6.7 (71 days): 2011-06-03, `commit 60a4a90 <https://github.com/python/cpython/commit/60a4a90c8dd2972eb4bb977e70835be9593cbbac>`_ (2011-03-24, 0 days)
* 2.7.2 (79 days): 2011-06-11, `commit 60a4a90 <https://github.com/python/cpython/commit/60a4a90c8dd2972eb4bb977e70835be9593cbbac>`_ (2011-03-24, 0 days)
* 3.1.4 (79 days): 2011-06-11, `commit a119df9 <https://github.com/python/cpython/commit/a119df91f33724f64e6bc1ecb484eeaa30ace014>`_ (2011-03-29, 5 days)
* 3.2.1 (108 days): 2011-07-10, `commit a119df9 <https://github.com/python/cpython/commit/a119df91f33724f64e6bc1ecb484eeaa30ace014>`_ (2011-03-29, 5 days)
* 3.3.0: 2012-09-29, `commit a119df9 <https://github.com/python/cpython/commit/a119df91f33724f64e6bc1ecb484eeaa30ace014>`_ (2011-03-29)


CVE-2011-4940
=============

The ``list_directory()`` function in ``Lib/SimpleHTTPServer.py`` in
``SimpleHTTPServer`` in Python before 2.5.6c1, 2.6.x before 2.6.7 rc2, and
2.7.x before 2.7.2 does not place a charset parameter in the Content-Type
HTTP header, which makes it easier for remote attackers to conduct
cross-site scripting (XSS) attacks against Internet Explorer 7 via UTF-7
encoding.

Information:

* Disclosure date: 2011-03-08 (issue #11442 reported).
* `CVSS Score`_: 2.6.

Links:

* http://bugs.python.org/issue11442
* http://www.cvedetails.com/cve/CVE-2011-4940/

Fixed In:

* 2.5.6 (79 days): 2011-05-26, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 2.6.7 (87 days): 2011-06-03, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 2.7.2 (95 days): 2011-06-11, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 3.2.4 (761 days): 2013-04-07, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 3.3.1 (761 days): 2013-04-07, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17, 9 days)
* 3.4.0: 2014-03-16, `commit 3853586 <https://github.com/python/cpython/commit/3853586e0caa0d5c4342ac8bd7e78cb5766fa8cc>`_ (2011-03-17)


CVE-2010-1634
=============

Multiple integer overflows in ``audioop.c`` in the ``audioop`` module in Python
2.6, 2.7, 3.1, and 3.2 allow context-dependent attackers to cause a denial
of service (application crash) via a large fragment, as demonstrated by a
call to audioop.lin2lin with a long string in the first argument, leading
to a buffer overflow.

NOTE: this vulnerability exists because of an incorrect fix for
`CVE-2008-3143`_.

Information:

* Disclosure date: 2010-05-10 (issue #8674 reported).
* `CVSS Score`_: 5.0.

Links:

* http://bugs.python.org/issue8674
* http://www.cvedetails.com/cve/CVE-2010-1634/

Fixed In:

* 2.6.6 (106 days): 2010-08-24, `commit 7ceb497 <https://github.com/python/cpython/commit/7ceb497ae6f554274399bd9916ea5a21de443208>`_ (2010-05-11, 1 days)
* 2.7: 2010-07-03, `commit 11bb2cd <https://github.com/python/cpython/commit/11bb2cdc6aa8db142a87de281b83293d500847b2>`_ (2010-05-11)
* 3.1.3 (201 days): 2010-11-27, `commit ee289e6 <https://github.com/python/cpython/commit/ee289e6cd5c009e641ee970cfc67996d8f871221>`_ (2010-05-11, 1 days)
* 3.2: 2011-02-20, `commit 393b97a <https://github.com/python/cpython/commit/393b97a7b61583f3e0401f385da8b741ef1684d6>`_ (2010-05-11)


CVE-2010-2089
=============

The ``audioop`` module in Python 2.7 and 3.2 does not verify the relationships
between size arguments and byte string lengths, which allows
context-dependent attackers to cause a denial of service (memory corruption
and application crash) via crafted arguments, as demonstrated by a call to
``audioop.reverse()`` with a one-byte string, a different vulnerability
than `CVE-2010-1634`_.

Information:

* Disclosure date: 2010-01-11 (issue #7673 reported).
* Reported by: STINNER Victor.
* `CVSS Score`_: 5.0.

Links:

* http://bugs.python.org/issue7673
* http://www.cvedetails.com/cve/CVE-2010-2089/

Fixed In:

* 2.6.6 (225 days): 2010-08-24, `commit e9123ef <https://github.com/python/cpython/commit/e9123efa21a16584758b5ce7da93d3966cf0cd81>`_ (2010-07-03, 173 days)
* 2.7.2 (516 days): 2011-06-11, `commit e9123ef <https://github.com/python/cpython/commit/e9123efa21a16584758b5ce7da93d3966cf0cd81>`_ (2010-07-03, 173 days)
* 3.1.3 (320 days): 2010-11-27, `commit 8e42fb7 <https://github.com/python/cpython/commit/8e42fb7ada3198e66d3f060c5c87c52465a86e36>`_ (2010-07-03, 173 days)
* 3.2: 2011-02-20, `commit bc5c54b <https://github.com/python/cpython/commit/bc5c54bca24fdb1fcf7fa055831ec997a65f3ce8>`_ (2010-07-03)


Issue #6791
===========

Limit the HTTP header readline.

Information:

* Disclosure date: 2009-08-28 (issue #6791 reported).
* Reported by: sumar (m.sucajtys).

Links:

* http://bugs.python.org/issue6791

Fixed In:

* 2.7.2 (652 days): 2011-06-11, `commit d7b6ac6 <https://github.com/python/cpython/commit/d7b6ac66c1b81d13f2efa8d9ebba69e17c158c0a>`_ (2010-12-18, 477 days)
* 3.1.4 (652 days): 2011-06-11, `commit ff1bbba <https://github.com/python/cpython/commit/ff1bbba92aad261df1ebd8fd8cc189c104e113b0>`_ (2010-12-18, 477 days)
* 3.2: 2011-02-20, `commit 5466bf1 <https://github.com/python/cpython/commit/5466bf1c94d38e75bc053b0cfc163e2f948fe345>`_ (2010-12-18)


CVE-2010-3492
=============

The ``asyncore`` module in Python before 3.2 does not properly handle
unsuccessful calls to the accept function, and does not have accompanying
documentation describing how daemon applications should handle unsuccessful
calls to the accept function, which makes it easier for remote attackers to
conduct denial of service attacks that terminate these applications via
network connections.

Information:

* Disclosure date: 2009-08-14 (issue #6706 reported).
* Reported by: Giampaolo Rodola.
* `CVSS Score`_: 5.0.

Links:

* http://bugs.python.org/issue6706
* http://www.cvedetails.com/cve/CVE-2010-3492/

Fixed In:

* 2.7.4 (1331 days): 2013-04-06, `commit 977c707 <https://github.com/python/cpython/commit/977c707b425ee753d54f3e9010f07ec77ef61274>`_ (2010-10-04, 416 days)
* 3.2: 2011-02-20, `commit 977c707 <https://github.com/python/cpython/commit/977c707b425ee753d54f3e9010f07ec77ef61274>`_ (2010-10-04)


CVE-2010-3493
=============

Multiple race conditions in ``smtpd.py`` in the ``smtpd`` module in Python 2.6,
2.7, 3.1, and 3.2 alpha allow remote attackers to cause a denial of
service (daemon outage) by establishing and then immediately closing a TCP
connection, leading to the accept function having an unexpected return
value of None, an unexpected value of None for the address, or an
ECONNABORTED, EAGAIN, or EWOULDBLOCK error, or the getpeername function
having an ENOTCONN error, a related issue to `CVE-2010-3492`_.

Information:

* Disclosure date: 2009-08-14 (issue #6706 reported).
* Reported by: Giampaolo Rodola.
* `CVSS Score`_: 4.3.

Links:

* http://bugs.python.org/issue6706
* http://www.cvedetails.com/cve/CVE-2010-3493/

Fixed In:

* 2.7.1 (470 days): 2010-11-27, `commit 19e9fef <https://github.com/python/cpython/commit/19e9fefc660d623ce7c31fb008cde1157ae12aba>`_ (2010-11-01, 444 days)
* 3.1.3 (470 days): 2010-11-27, `commit 5ea3d0f <https://github.com/python/cpython/commit/5ea3d0f95b51009fa1c3409e7dd1c12006427ccc>`_ (2010-11-01, 444 days)
* 3.2.1 (695 days): 2011-07-10, `commit 5ea3d0f <https://github.com/python/cpython/commit/5ea3d0f95b51009fa1c3409e7dd1c12006427ccc>`_ (2010-11-01, 444 days)
* 3.3.0: 2012-09-29, `commit 5ea3d0f <https://github.com/python/cpython/commit/5ea3d0f95b51009fa1c3409e7dd1c12006427ccc>`_ (2010-11-01)


CVE-2008-2315
=============

Security patches from Apple: prevent integer overflows when allocating
memory.

CVE-ID:

* CVE-2008-1679 (``imageop``)
* CVE-2008-1721 (``zlib``)
* CVE-2008-1887 (``PyString_FromStringAndSize()``)
* CVE-2008-2315
* CVE-2008-2316 (``hashlib``)
* CVE-2008-3142 (``unicode_resize()``, ``PyMem_RESIZE()``)
* CVE-2008-3144 (``PyOS_vsnprintf()``)
* CVE-2008-4864 (``imageop``)

Information:

* Disclosure date: 2008-07-31 (commit).
* `CVSS Score`_: 7.5.

Links:

* https://lists.apple.com/archives/security-announce/2009/Feb/msg00000.html
* http://www.cvedetails.com/cve/CVE-2008-1679/
* http://www.cvedetails.com/cve/CVE-2008-1721/
* http://www.cvedetails.com/cve/CVE-2008-1887/
* http://www.cvedetails.com/cve/CVE-2008-2315/
* http://www.cvedetails.com/cve/CVE-2008-2316/
* http://www.cvedetails.com/cve/CVE-2008-3142/
* http://www.cvedetails.com/cve/CVE-2008-3144/
* http://www.cvedetails.com/cve/CVE-2008-4864/

Fixed In:

* 2.6.0 (62 days): 2008-10-01, `commit e7d8be8 <https://github.com/python/cpython/commit/e7d8be80ba634fa15ece6f503c33592e0d333361>`_ (2008-07-31, 0 days)
* 3.0.0: 2008-12-03, `commit 3ce5d92 <https://github.com/python/cpython/commit/3ce5d9207e66d61d4b0502cf47ed2d2bcdd2212f>`_ (2008-08-24)


CVE-2008-3143
=============

Multiple integer overflows in Python before 2.5.2 might allow
context-dependent attackers to have an unknown impact via vectors related
to:

* ``Include/pymem.h``
* ``Modules/``:

  - ``_csv.c``
  - ``_struct.c``
  - ``arraymodule.c``
  - ``audioop.c``
  - ``binascii.c``
  - ``cPickle.c``
  - ``cStringIO.c``
  - ``datetimemodule.c``
  - ``md5.c``
  - ``rgbimgmodule.c``
  - ``stropmodule.c``

* ``Modules/cjkcodecs/multibytecodec.c``
* ``Objects/``:

  - ``bufferobject.c``
  - ``listobject.c``
  - ``obmalloc.c``

* ``Parser/node.c``
* ``Python/``:

  - ``asdl.c``
  - ``ast.c``
  - ``bltinmodule.c``
  - ``compile``

as addressed by "checks for integer overflows, contributed by Google."

Information:

* Disclosure date: 2008-04-11 (issue #2620 reported).
* Reported by: Justin Ferguson.
* `CVSS Score`_: 7.5.

Links:

* http://bugs.python.org/issue2620
* http://www.cvedetails.com/cve/CVE-2008-3143/

Fixed In:

* 2.5.3 (252 days): 2008-12-19, `commit 83ac014 <https://github.com/python/cpython/commit/83ac0144fa3041556aa4f3952ebd979e0189a19c>`_ (2008-07-28, 108 days)
* 2.6: 2008-10-01, `commit 0470bab <https://github.com/python/cpython/commit/0470bab69783c13447cb634fa403ef1067fe56d1>`_ (2008-07-22)
* 3.0: 2008-12-03, `commit d492ad8 <https://github.com/python/cpython/commit/d492ad80c872d264ed46bec71e31a00f174ac819>`_ (2008-07-23)


CVE-2008-5031
=============

Multiple integer overflows in Python 2.2.3 through 2.5.1, and 2.6, allow
context-dependent attackers to have an unknown impact via a large integer
value in the tabsize argument to the expandtabs method, as implemented by:

* the ``string_expandtabs()`` function in ``Objects/stringobject.c``
* the ``unicode_expandtabs()`` function in ``Objects/unicodeobject.c``

NOTE: this vulnerability reportedly exists because of an incomplete
fix for `CVE-2008-2315`_.

Information:

* Disclosure date: 2008-03-11 (commit date).
* Reported by: Chris Evans.
* `CVSS Score`_: 10.0.

Links:

* http://scary.beasts.org/security/CESA-2008-008.html
* http://www.cvedetails.com/cve/CVE-2008-5031/

Fixed In:

* 2.5.3 (283 days): 2008-12-19, `commit 44a93e5 <https://github.com/python/cpython/commit/44a93e54f4b0f90634d16d53c437fabb6946ea9d>`_ (2008-03-11, 0 days)
* 2.6: 2008-10-01, `commit 5bdff60 <https://github.com/python/cpython/commit/5bdff60617e6fc1d2e387a0b165cb23b82d7dae6>`_ (2008-03-11)
* 3.0: 2008-12-03, `commit dd15f6c <https://github.com/python/cpython/commit/dd15f6c315f20c1a9a540dd757cd63e27dbe9f3c>`_ (2008-03-16)


CVE-2011-1015
=============

The ``is_cgi()`` method in ``CGIHTTPServer.py`` in the ``CGIHTTPServer``
module in Python 2.5, 2.6, and 3.0 allows remote attackers to read script
source code via an HTTP GET request that lacks a ``/`` (slash) character at
the beginning of the URI.

Information:

* Disclosure date: 2008-03-07 (issue #2254 reported).
* `CVSS Score`_: 5.0.

Links:

* http://bugs.python.org/issue2254
* http://www.cvedetails.com/cve/CVE-2011-1015/

Fixed In:

* 2.7 (848 days): 2010-07-03, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06, 395 days)
* 3.2.4 (1857 days): 2013-04-07, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06, 395 days)
* 3.3.1 (1857 days): 2013-04-07, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06, 395 days)
* 3.4.0: 2014-03-16, `commit 923ba36 <https://github.com/python/cpython/commit/923ba361d8f757f0656cfd216525aca4848e02aa>`_ (2009-04-06)


CVE-2007-4965
=============

Multiple integer overflows in the ``imageop`` module in Python 2.5.1 and
earlier allow context-dependent attackers to cause a denial of service
(application crash) and possibly obtain sensitive information (memory
contents) via crafted arguments to (1) the ``tovideo()`` method, and
unspecified other vectors related to (2) ``imageop.c``, (3)
``rbgimgmodule.c``, and other files, which trigger heap-based buffer
overflows.

CVE-2009-4134, CVE-2010-1449 and CVE-2010-1450 are similar reports of the
same vulnerability. Reported again by Marc Schoenefeld in the Red Hat
bugzilla at 2009-11-26.

Information:

* Disclosure date: 2007-09-16 (full-disclosure email).
* Reported by: Slythers Bro (on the full-disclosure mailing list).
* `CVSS Score`_: 5.8.

Links:

* http://bugs.python.org/issue1179
* http://seclists.org/fulldisclosure/2007/Sep/279
* http://bugs.python.org/issue8678
* https://bugzilla.redhat.com/show_bug.cgi?id=541698
* http://www.cvedetails.com/cve/CVE-2007-4965/
* http://www.cvedetails.com/cve/CVE-2009-4134/
* http://www.cvedetails.com/cve/CVE-2010-1449/
* http://www.cvedetails.com/cve/CVE-2010-1450/

Fixed In:

* 2.5.3 (460 days): 2008-12-19, `commit 4df1b6d <https://github.com/python/cpython/commit/4df1b6d478020ac51c84467f47e42083f53adbad>`_ (2008-08-19, 338 days)
* 2.6: 2008-10-01, `commit 93ebfb1 <https://github.com/python/cpython/commit/93ebfb154456daa841aa223bd296422787b3074c>`_ (2008-08-19)
