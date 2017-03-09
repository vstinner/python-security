+++++++++
TODO list
+++++++++

TODO list for this python-security documentation.

* Get discovered date from Python bug report?
* Get CVSS Score from the CVE?
* Get Red Hat impact from a Red Hat URL?

"Issue #19435": Python 3.1 is vulnerable, fix commited but never released

Expat::

    - name: "Issue #26556: Expat 2.1.1"
      disclosure: "2016-03-14 (issue #26556 reported)"
      discovered-at: "2015-07-24 (Expat issue #528 reported)"
      CVE-2015-1283

cookielib
=========

Add https://hackerone.com/reports/26647 vulnerability.

https://bugs.python.org/issue16611
   #16611: BaseCookie now parses 'secure' and 'httponly' flags.
https://bugs.python.org/issue22796
  Regression in Python 3.2 cookie parsing
https://bugs.python.org/issue25228
  Support for httponly/secure cookies reintroduced lax parsing behavior
https://code.djangoproject.com/ticket/26158
  cookie parsing fails with python 3.x if request contains unnamed cookie

YAML template::

    - name: "Issue #22796"
      summary: >
        hardened HTTP cookie parsing
      links:
        - http://bugs.python.org/issue22796
      disclosure: "2014-11-04 (issue #22796 created)"
      fixed-in:
       - b1e36073cdde71468efa27e88016aa6dd46f3ec7 # 3.x
      description: >
        HTTP cookie parsing is now stricter, in order to protect against potential
        injection attacks.

        Reported by Tim Graham.

