==========================================
Authentication Flaws in 2FA and API Tokens
==========================================

Introduction
============

PyPI implemented 2FA and API Tokens in 2019 as part of funded work to better
secure the service for Project Maintainers and Python users installing from
the index.

Two flaws were identified in the authentication policies which allowed API
Tokens and Basic Authentication to access resources they should not have had
access to, additionally bypassing two factor authentication.

* Disclosure date: **2020-01-05** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: Joachim Jablon
* Bounty awarded to discloser: $500 USD for multiple reports in Q1 2020

Reported vulnerabilities
========================

Web UI Authentication and 2FA bypass via API Tokens (Macaroons)
---------------------------------------------------------------

API tokens are advertised as only being valid for uploads, however by setting
the appropriate header, :code:`Authorization: token pypi-.....`, requests for
arbitrary actions could be made with the equivalent of a standard session.

Thus leaked API tokens regardless of scope may have had a much bigger impact
than advertised (uploading rogue releases vs deleting releases/projects or
modifying user account components)

Initially resolved in: https://github.com/pypa/warehouse/pull/7184

Web UI 2FA bypass via Basic Auth
--------------------------------

Similar to above, constructing and setting the appropriate header,
:code:`Authorization: Basic <base64>`, requests for arbitrary actions could be
made with the equivalent of a standard session.

Thus, 2FA bypass was possible if an attacker had the username and password for
a user.

Initially resolved in: https://github.com/pypa/warehouse/pull/7186

Assessment
==========

We are unable to directly determine if either of these vulnerabilities were
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

* 2020-01-05 Issue reported by Joachim Jablon to security@python.org per PyPI
  security policy on `pypi.org <https://pypi.org/security/>`_
* 2020-01-05 (**+0days**): Reports investigated by Ernest W. Durbin III and
  determined to be valid.
* 2020-01-05 (**+0days**): Fixes deployed and verified.
