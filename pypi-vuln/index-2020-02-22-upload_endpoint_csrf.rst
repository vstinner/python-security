==================================
Upload endpoint CSRF vulnerability
==================================

Summary
=======

A `Cross Site Request Forgery <https://owasp.org/www-community/attacks/csrf>`_
vulnerability was discovered in the endpoint which accepts uploads to PyPI.

* Disclosure date: **2020-02-22** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: Joachim Jablon
* Bounty awarded to discloser: $500 USD for multiple reports in Q1 2020

Reported vulnerability
======================

Upload endpoint vulnerable to CSRF
----------------------------------

Although PyPI implements CSRF protection for endpoints with side effects
throughout the views and endpoints for the primary web user interface, that
protection is not implemented for the upload endpoint at
https://upload.pypi.org/legacy/. This endpoint is not intended for browsers,
but rather clients such as `setuptools <https://setuptools.readthedocs.io/en/latest/>`_
and `twine <https://twine.readthedocs.io>`_ which do not authenticate using
HTTP Sessions or Cookies.

The upload endpoint was misconfigured to accept HTTP Session authentication
cookies from pypi.org. Combined with intentional disabling of CSRF protection
on this endpoint, an attacker could have constructed a form to trick PyPI users
into uploading releases to PyPI.

Initially resolved in: https://github.com/pypa/warehouse/pull/7432

Assessment
==========

We are unable to directly determine if this vulnerabilities was
exploited. PyPI stores an Audit Log of events modifying user accounts and
projects on the service. These log successful logins via the login form but
were not configured to log authentication via other methods as they were
assumed to be associated with package uploads only, which are logged
separately.

Reccomendations
===============

Users are encouraged to review their `Account Security History <https://pypi.org/manage/account/#account-events>`_
regularly to determine if any suspicious activity has taken place. If you
identify any such activity, please report it per `our published security policy <https://pypi.org/security/>`_. 

Timeline
========

* 2020-02-22 Issue reported by Joachim Jablon to security@python.org per PyPI
  security policy on `pypi.org <https://pypi.org/security/>`_
* 2020-02-23 (**+1days**): Report investigated by Ernest W. Durbin III and
  determined to be valid.
* 2020-02-24 (**+2days**): Fixes reviewd by PyPI administrators, deployed, and
  verified.
