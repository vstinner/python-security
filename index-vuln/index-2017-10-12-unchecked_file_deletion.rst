.. _index-unchecked_file_deletion:

Index Vulnerability: Unchecked File Deletion
============================================

Improper checking of ACLs would have allowed any authenticated user to delete
any release file hosted on the Package Index by supplying its md5 to the
``:files`` action in `the pypi-legacy <https://github.com/pypa/pypi-legacy>`_
code base.

* Disclosure date: **2017-10-12** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: `Max Justicz <https://mastodon.mit.edu/@maxj>`_

Fixed In
--------

* PyPI "Legacy Codebase" (2017-10-12) fixed by `commit 18200fa <https://github.com/pypa/pypi-legacy/commit/18200fa6731faeeda2433dd1c61d04373ad8a653>`_ (2017-10-12)

Audit
-----

After mitigating the attack vector and deploying it, the responding Package
Index maintainer worked to verify that no release files had been improperly
removed using this exploit.

The Package Index maintains an audit log in the form of a "Journal" for all
actions initiated. It was determined that exploitation of this attack vector
would still remove files via the `existing interface <https://github.com/pypa/pypi-legacy/blob/59e2e063b9ed887e3e5e00b7f4dc265150402d3d/webui.py#L2453>`_
an audit log would still be `written <https://github.com/pypa/pypi-legacy/blob/59e2e063b9ed887e3e5e00b7f4dc265150402d3d/store.py#L1987-L1988>`_.

Using this information, we were able to reconstruct the users with access to
legitimately remove release files at point in time of each file removal
`using the audit log <https://gist.github.com/ewdurbin/ba3304b6c0d6c48ccace903d3a567755>`_.

The output of this script were used to determine that no malicious actors
exploited this vulnerability. All flagged journal entries were related to one
of the following scenarios:

* Username updates that were not properly updated in the Journal
* Administrator intervention to remove packages

Timeline
--------

Timeline using the disclosure date **2017-10-12** as reference:

* 2017-10-12: Issue reported by `Max Justicz <https://mastodon.mit.edu/@maxj>`_ following guidelines in security policy on `pypi.org <https://pypi.org/security/>`_
* 2017-10-12 (**+0days**): Report investigated by `Ernest W. Durbin III <https://ernest.ly>`_ and determined to be exploitable
* 2017-10-12 (**+0days**): Fix implemented and deployed in `commit 18200fa <https://github.com/pypa/pypi-legacy/commit/18200fa6731faeeda2433dd1c61d04373ad8a653>`_
* 2017-10-12 (**+0days**): The audit journals maintained by PyPI were used to reconstruct the full history of file removals to determine that no malicious deletions were performed.
