=================================================
Vulnerability in Legacy Document Deletion on PyPI
=================================================

An exploitable vulnerability in the mechanisms for deleting legacy
documentation hosting deployment tooling on `PyPI <https://pypi.org>`_ was
discovered by a security researcher, which would allow an attacker to remove documentation for projects not under their control.

* Disclosure date: **2020-07-25** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: `RyotaK <https://twitter.com/ryotkak>`_

Summary
=======

At one point PyPI supported uploading documentation in addition to distribution
files. This functionality was under-utilized and slowly deprecated/removed
starting in `2016
<https://github.com/pypa/setuptools/issues/604#issuecomment-223614048>`_ and
was not included in the 2018 re-write of PyPI.

Instead, for projects that had previously hosted documentation on PyPI, the new PyPI
presented them with the ability to remove/destroy the existing documentation on
PyPI in favor of using an external service.

To quote the discloser:

    This feature is added a few years ago by this pull request:
    https://github.com/pypa/warehouse/pull/3413 As you can see from the pull
    request above, there is an endpoint located at
    ``manage/project/{project_name}/delete_project_docs/`` that deletes the
    legacy documentation.  And this endpoint calls the ``destroy_docs`` function
    which passes ``project.name`` into ``remove_documentation`` function.

    Then, ``remove_documentation`` passes ``project_name`` into the ``remove_by_prefix``
    function of ``S3DocsStorage``.

    Since ``remove_by_prefix`` uses list_objects_v2 with the prefix, all files
    that start with the specified project name will be returned. (e.g. If ``p``
    is specified in the prefix, it will return pypi, pip, python... etc.)
    As far as I can see from these codes, there is no suffix in the project
    name (e.g. ``/``).

    This means that if there is a project called ``examp``, and their owner
    decides to delete the legacy documentation, documentation for projects that
    have a name starting with ``examp`` will be deleted. (e.g. ``example``)


Analysis
========

Many projects implement "psuedonamespaces" on PyPI, for discoverability and
organizational purposes, particularly those which implement plugin or extension
frameworks. In our analysis, the only impact of this vulnerability appears to
have been accidental, in which maintainers for a top-level project (e.g. ``framework``)
intentionally initiated documentation deletion for their project, which then
cascaded to plugin/extension projects which shared the prefix (e.g. ``framework.foo``, ``framework-bar``).

Mitigation
==========

This vulnerability was fixed in https://github.com/pypa/warehouse/pull/9839 via
https://github.com/pypa/warehouse/pull/9839/commits/3afcac795619b0b06007d0fb179d3ca137ed43b7
by adding a trailing slash to the project name used with ``remove_by_prefix``.

Audit
=====

A dump of Project ``name`` and ``has_docs`` flags from the database, Journal
and Project Event records implemented by PyPI, along with a full listing of the
documentation hosting S3 bucket were collected for audit and analysis.

By comparing the ``has_docs`` flag for each Project with the status of matching
documentation in the S3 bucket listing, we were able to identify 96 Projects
out of 3,632 for which the flag in the database was incorrect.

This delta represents projects for which documentation on the legacy hosting
service is "missing".

77 of the missing Project documents were identified as being accidentally
deleted due to the extension/plugin concern discussed in the Analysis section.

The remaining 19 missing Project documents are not explainable via the
vulnerability disussed here, as no ``docdestroy`` events are recorded which
share the prefix for their name. The legacy document hosting service
administration has varied over the years, and it is very likely that these
documents were directly removed by administrators or lost during migrations and
recovery attempts.

Timeline
========

* 2018-03-25: "Destroy documentation" feature added in (PR #3413)
* 2021-07-25: Issue reported by `RyotaK <https://twitter.com/ryotkak>`_
  following guidelines in security policy on `pypi.org
  <https://pypi.org/security/>`_)
* 2021-07-26 (**+1days**): Fix is implemented and deployed in `commit 036fdc <https://github.com/pypa/warehouse/commit/036fdcb99106b8f26effec67d8c2e8caa44c3275>`_
