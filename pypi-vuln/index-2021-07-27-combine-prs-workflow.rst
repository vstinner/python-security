=================================================
Vulnerability in GitHub Actions Workflow for PyPI
=================================================

An exploitable vulnerability in a GitHub Actions Workflow for PyPI's source
repository could allow an attacker to obtain write permissions against the
pypa/warehouse repository.

* Disclosure date: **2020-07-25** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: `RyotaK <https://twitter.com/ryotkak>`_
* Bounty awarded to discloser: $1,000 USD for multiple reports in 2021-07

Summary
=======

TODO - some details about why the workflow exists

To quote the security researcher:

    As ``combine-prs.yml`` will pick up pull requests that have ``dependabot`` as a
    prefix in the ``head.ref``, it's possible to force this workflow to pick up a
    malicious pull request.

    (As ``head.ref`` will return branch name even if it's in the forked
    repository, someone may create a branch name like ``dependabotasdf`` and
    it'll be picked by this workflow.)

    Since branch names can contain shell metacharacters, this line would be
    unsafe as the ``${{ }}`` expression is used.  Because the ``${{ }}`` expression
    is evaluated before commands are passed to bash, it makes this workflow
    vulnerable to command injection.

    By combining these vulnerabilities, it's possible to obtain write
    permissions against the ``pypa/warehouse`` repository by the following ways:

    1. Fork pypa/workhouse.
    2. In forked repository, create a branch named
       ``dependabot;cat$IFS$(echo$IFS'LmdpdA=='|base64$IFS'-d')/config|base64;#``
       (This command will execute ``cat .git/config | base64``. As
       actions/checkout leaves GitHub token in the ``.git/config`` file by
       default, it's possible to obtain it from there.)
    3. Add harmless modification to the created branch.
    4. Create a pull request with a harmless name (e.g. "WIP")
    5. Wait for Combine PRs to be triggered.
    6. GitHub Token with write permissions against ``pypa/warehouse`` will be leaked.

Analysis
========

TODO

Mitigation
==========

This vulnerability was fixed in https://github.com/pypa/warehouse/pull/9846 via
https://github.com/pypa/warehouse/pull/9846/commits/fb98c6bb4d68fb43944171214971f6c776f844ce
and
https://github.com/pypa/warehouse/pull/9846/commits/50bd16422889d653127d373c9615516bf883a394
by matching against the PR creator username and not using an unecessary
``echo``.

Audit
=====

TODO

Timeline
========

* 2020-10-12: "Combine PRs" workflow added in (PR #8694)
* 2021-07-25: Issue reported by `RyotaK <https://twitter.com/ryotkak>`_
  following guidelines in security policy on `pypi.org
  <https://pypi.org/security/>`_)
* 2021-07-26 (**+1days**): Fix is implemented and deployed in `commit 33ad32 <https://github.com/pypa/warehouse/commit/33ad326aab676b74bde3ecad686cf144e8c98fc9>`_
