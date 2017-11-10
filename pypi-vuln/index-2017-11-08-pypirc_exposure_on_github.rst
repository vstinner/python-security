.. _index-unchecked_file_deletion:

PyPI credential exposure on GitHub
==================================

Introduction
------------

A common mistake made by users is committing and publishing "dotfiles"
containing private material such as passwords, API keys, or cryptographic keys
to public repositories on services such as GitHub.

Compounding this issue, the Python packaging ecosystem historically and
currently encourages---albeit with some level of caution---the use of a
``.pypirc`` file for storage of passwords consumption by packaging tools. For a
summary of the dangers of this methodology, see `this article on securing PyPI
credentials <https://glyph.twistedmatrix.com/2017/10/careful-with-that-pypi.html>`_.

With ever strengthening search tools on GitHub attackers are able to formulate
queries which quickly identify and obtain credentials from such hosting sites.

* Disclosure date: **2017-11-05** (Reported via security policy on `pypi.org <https://pypi.org/security/>`_)
* Disclosed by: Joachim Jablon

Report
------

The PyPI security team was notified by Joachim Jablon that ``.pypirc`` files
containing valid PyPI credentials were obtainable with a straightforward search
and scrape of GitHub.

Using tools developed by the reporter the PyPI security team was able to
identify 77 valid PyPI logins in 85 public files published to GitHub. These 77
logins had maintainer or administrator access to 146 unique projects on PyPI.

Audit
-----
Action Taken by PyPI team

The PyPI security team followed up by auditing and extending the Proof of
Concept tools supplied by the reporter to verify the report.

After running the tooling against the full result set of the GitHub code search
the PyPI administrators unset the passphrases for all valid logins found and
issued an administrative password reset for exposed users.

Additionally an audit of PyPI's journals showed no signs of malicious access
for the exposed accounts.

The email sent to affected users took the form

.. code-block::

  From: admin@mail.pypi.python.org
  To: {user['email']}
  Subject: [Urgent] Your PyPI password has been reset
  
  {username},
  
  A security report recently identified that your PyPI login credentials were
  exposed in a public code repository on github.com.
  
  Please see the following links where your credentials were found:
  
  {pypirc_links}
  
  An initial audit of our journals found that {package_count} projects your
  account has access to were potentially exposed but did not indicate any
  malicious activity.
  
  Packages:
  
  {packages}
  
  Please double check the audit logs at https://pypi.python.org after you have
  reset your password and notify us if you identify any suspicious activity.
  
  Also please reset your passwords anywhere else you may have used the password
  exposed in the above links.
  
  To reset your password, please visit {password_reset_link}.
  
  Thanks,
  PyPI Security Team

Recommendations
---------------

All users of PyPI should ensure that their PyPI login credentials are safe and
have not been inadvertently exposed in a public repository of dotfiles, in the
root of a project directory, or in some other public or shared medium.

The PyPI team does not have the resources to search or scrape all such services
and may not have identified all forms of this exposure.

Additionally, reviewing the Audit Journal for your projects on pypi.python.org
for suspicous activity is a good idea. If you identify any such activity,
please report it per `our published security policy <https://pypi.org/security/>`_.

Timeline
--------

Timeline using the disclosure date **2017-11-05** as reference:

* 2017-11-05 Issue reported by Joachim Jablon to a single member of the security team listed in our security policy on `pypi.org <https://pypi.org/security/>`_
* 2017-11-08 (**+3days**):Issue reported by Joachim Jablon to an additional member of the security team listed in our security policy on `pypi.org <https://pypi.org/security/>`_
* 2017-11-08 (**+3days**):Issue reported by Joachim Jablon to all members of the security team listed in our security policy on `pypi.org <https://pypi.org/security/>`_
* 2017-10-08 (**+3days**): Report investigated by `Ernest W. Durbin III <https://ernest.ly>`_ and determined to be valid. 
* 2017-10-09 (**+4days**): Administrative password resets issued.
