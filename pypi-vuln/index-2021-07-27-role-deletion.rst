======================================
Vulnerability in Role Deletion on PyPI
======================================

An exploitable vulnerability in the mechanisms for deleting roles on `PyPI
<https://pypi.org>`_ was discovered by a security researcher, which would allow
an attacker to remove roles for projects not under their control.

* Disclosure date: **2021-07-26** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: `RyotaK <https://twitter.com/ryotkak>`_
* Bounty awarded to discloser: $1,000 USD for multiple reports in 2021-07

Summary
=======

PyPI has two types of permissions for users relative to projects: ``Owner`` and
``Maintainer``. Permissions are stored by mapping a user ID to a project ID,
with a permission, as a role. Each role has a unique ID.

PyPI users have the ability to remove roles for the projects they have the
``Owner`` role for. This is done via a web form by ``POST``-ing the role ID to
an endpoint dedicated to deleting roles.

This endpoint is guarded by a permissions check to ensure the current user has
the ``Owner`` role on the current project. However, when querying for the role
by ID, the query was missing a check that the current project matches the
project the role is associated with.

This would enable any user to delete any role if they were able to procure a
valid role ID.

Analysis
========

Role IDs are represented on PyPI as UUIDs, and are therefore pseudo-random and
not enumerable. In addition, role IDs for a given project are only exposed to
any user with the ``Owner`` role on that project (via the same webform for
deleting roles).

Given this, the PyPI administrators determined that it would not be possible
for an attacker to acquire a role ID that they didn't already have the ability
to delete, and that any successful exploitation of this vulnerability would
require a high volume of requests in attempt to brute force a role ID. In
addition, any successful exploitation would only have the ability to remove a
random role ID, and not a role for a specific user or project.

Mitigation
==========

This vulnerability was fixed in https://github.com/pypa/warehouse/pull/9845 via
https://github.com/pypa/warehouse/pull/9845/commits/7605bee1e77319000f71f5b60959a35c8e482161
by adding a filter on the current project to the query for the role.

Audit
=====

The PyPI administrators analyzed incidences of high-volume traffic to the role
deletion endpoint, and found two days where the quantity of requests to this
endpoint were far above average (>200 requests per day). The PyPI
administrators analyzed all role deletions on these days and found them to be
legitimate bulk removals of roles.

Timeline
========

* 2018-01-22: "Role management" feature added in (PR #2705)
* 2021-07-26: Issue reported by `RyotaK <https://twitter.com/ryotkak>`_
  following guidelines in security policy on `pypi.org
  <https://pypi.org/security/>`_)
* 2021-07-27 (**+1days**): Fix is implemented and deployed in `commit 7605be
  <https://github.com/pypa/warehouse/pull/9845/commits/7605bee1e77319000f71f5b60959a35c8e482161>`_
