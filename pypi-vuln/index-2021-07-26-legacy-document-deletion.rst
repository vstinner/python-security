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

TODO

Mitigation
==========

This vulnerability was fixed in https://github.com/pypa/warehouse/pull/9839 via
https://github.com/pypa/warehouse/pull/9839/commits/3afcac795619b0b06007d0fb179d3ca137ed43b7
by adding a trailing slash to the project name used with ``remove_by_prefix``.

Audit
=====

TODO

Timeline
========

* 2018-03-25: "Destroy documentation" feature added in (PR #3413)
* 2021-07-25: Issue reported by `RyotaK <https://twitter.com/ryotkak>`_
  following guidelines in security policy on `pypi.org
  <https://pypi.org/security/>`_)
* 2021-07-26 (**+1days**): Fix is implemented and deployed in `commit 036fdc <https://github.com/pypa/warehouse/commit/036fdcb99106b8f26effec67d8c2e8caa44c3275>`_
