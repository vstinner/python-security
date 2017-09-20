+++++++++++++++++
Packages and PyPI
+++++++++++++++++

Check for known vulnerabilities
===============================

* https://github.com/pyupio/safety-db and https://pyup.io/
* `safety package <https://pypi.python.org/pypi/safety>`_: Safety checks your
  installed dependencies for known security vulnerabilities.

GPG
===

* `Verifying PyPI and Conda Packages
  <http://stuartmumford.uk/blog/verifying-pypi-and-conda-packages.html>`_
  by Stuart Mumford (2016-06-21)
* `Sign a package using GPG and Twine
  <https://packaging.python.org/tutorials/distributing-packages/#upload-your-distributions>`_

pip security
============

* pip: `Implement "hook" support for package signature verification
  <https://github.com/pypa/pip/issues/1035>`_

PyPI
====

* `PEP 458 -- Surviving a Compromise of PyPI
  <https://www.python.org/dev/peps/pep-0458/>`_ (27-Sep-2013)
* `PEP 480 -- Surviving a Compromise of PyPI: The Maximum Security Model
  <https://www.python.org/dev/peps/pep-0480/>`_ (8-Oct-2014)
* `Making PyPI security independent of SSL/TLS
  <http://www.curiousefficiency.org/posts/2016/09/python-packaging-ecosystem.html#making-pypi-security-independent-of-ssl-tls>`_
  by Nick Coghlan

PyPI typo squatting
===================

* `Typosquatting programming language package managers
  <http://incolumitas.com/2016/06/08/typosquatting-package-managers/>`_
  by Nikolai Tschacher (8 June, 2016)
* `LWN: Typosquatting in package repositories
  <https://lwn.net/Articles/694830/>`_ (July 20, 2016)
* `Building a botnet on PyPi
  <https://hackernoon.com/building-a-botnet-on-pypi-be1ad280b8d6>`_
  by Steve Stagg (May 19, 2017)
* warehouse bug (pypi.org): `Block package names that conflict with core
  libraries <https://github.com/pypa/warehouse/issues/2151>`_ (reported at June
  28, 2017)
* 2017-09-09: `skcsirt-sa-20170909-pypi-malicious-code advisory
  <http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/>`_

fate0:

* 2017-05-27 04:38 - 2017-05-31 12:24 (5 days): 10,685 downloads
* May-June, 2017
* https://mail.python.org/pipermail/distutils-sig/2017-June/030592.html
* http://blog.fatezero.org/2017/06/01/package-fishing/
* https://github.com/pypa/pypi-legacy/issues/644
* http://evilpackage.fatezero.org/
* https://github.com/fate0/cookiecutter-evilpy-package
* Packages (this list needs to be validated):

  * caffe
  * ffmpeg
  * ftp
  * git
  * hbase
  * memcached
  * mkl
  * mongodb
  * opencv
  * openssl
  * phantomjs
  * proxy
  * pygpu
  * python-dev
  * rabbitmq
  * requirement.txt
  * requirements.txt
  * rrequirements.txt
  * samba
  * shadowsock
  * smb
  * tkinter
  * vtk
  * youtube-dl
  * zookeeper
  * ztz
  * ...

See also:

* `pytosquatting.org project <https://www.pytosquatting.org/>`_

Example of typos:

* ``urllib``, ``urllib2``: part of the standard library
* ``urlib3`` instead of ``urllib3``

Links
=====

* `The Update Framework (TUF) <https://theupdateframework.github.io/>`_:
  Like the S in HTTPS, a plug-and-play library for securing a software updater.
