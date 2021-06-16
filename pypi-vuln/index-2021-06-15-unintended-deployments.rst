======================================
Unintended Deployments to PyPI Servers
======================================

Summary
=======

On June 15, 2021 an exploitable vulnerability in the deployment tooling for
`PyPI <https://pypi.org>`_ was discovered by a PyPI administrator.

This vulnerability allowed for arbitrary code which passed the continuous
integration suite to be deployed to the servers that run PyPI without approval
or merge to the `warehouse codebase <https://github.com/pypa/warehouse>`_.

Two instances of unmerged and unapproved changes being deployed were discovered:

* March 17, 2021 - https://github.com/pypa/warehouse/pull/9245
* June 15, 2021 - https://github.com/pypa/warehouse/pull/9669

In both cases, there was no malicious intent and the changes would later be
approved and merged by PyPI administrators.

In review and audit, PyPI administrators were able to confirm that no other
actors attempted or succeeded in initiating an unapproved deployment.

Analysis
========

The root cause of this vulnerability was misinterpretation of the ``check_suite``
event from GitHub. Initially it was thought that the value for
``repository->full_name`` in the payload was the repository from which the commit
under test originated, when in actuality it is the repository in which the
check suite ran.

::

    installation_id = hook.payload['installation']['id']
    repository_name = hook.payload['repository']['full_name']
    branch_names = [hook.payload['check_suite']['head_branch']]
    
    applications = Application.query.filter(and_(
        Application.auto_deploy_branch.in_(branch_names),
        Application.github_app_installation_id == installation_id,
        Application.github_repository == repository_name,
    )).all()

When filtering the repository name and branch to determine if a deployment was
required, as above, this allowed for any Pull Request opened against the
repository originating from any branch called ``main`` to initiate a deploy as
long as the continuous integration run succeeded.

Mitigation
==========
Because the payload of the ``check_suite`` hook does not contain the necessary
information to determine the original repository to which the branch and commit
belong, our deployment tooling began processing ``push`` events.

The ``push`` event is only fired for branches belonging to the repository, but
can be further verified by checking the value of
``hook.payload['repository']['full_name']`` and ``hook.payload['ref']`` to ensure
that it originated from the authentic
`warehouse repository <https://github.com/pypa/warehouse>`_.

``push`` events which could potentially initiate a deployment are marked as such,
in this case that they originate from the specific repository and branch
configured (``pypa/warehouse:main``).

All further ``check_suite`` events are filtered on wether or a not an associated
``push`` event was marked as deployable.

This was validated via a
`test Pull Request <https://github.com/pypa/warehouse/pull/9672>`_.
No deployment was initiated until after merge.

Audit
=====

The deployment tooling for PyPI keeps a full history of all inbound hooks it
has received, and the actions taken after processing.

In review, we were able to identify the two unintended deployments using this
log and review them. No other instances, malicious or accidental, of this were
observed.

Timeline
========

* 2020-08-21 Deployment tooling updated to use the ``check_suite`` hook rather
  than ``status`` hook from GitHub to initiate deploys.
* 2021-03-17 First instance (PR #9245) of unintentional deploy
* 2021-06-15 Second instance (PR #9669) of unintentional deploy
* 2021-06-15 PyPI Administrator alerts team to suspicious deployment notifications on PR #9669
* 2021-06-15 Deployment tooling for PyPI disabled
* 2021-06-15 Fix developed and tested
* 2021-06-15 Deployment tooling for PyPI re-enabled
