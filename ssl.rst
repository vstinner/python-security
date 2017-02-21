+++++++++++++++++++++++++++
Python SSL and TLS security
+++++++++++++++++++++++++++

Evolutions of the ``ssl`` module.

Cipher suite
============

Python 2.7 and 3.5-3.7::

    _DEFAULT_CIPHERS = (
        'ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:'
        'ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:'
        '!aNULL:!eNULL:!MD5:!3DES'
        )

Pytohn 3.4::

    _DEFAULT_CIPHERS = (
        'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
        'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
        '!eNULL:!MD5'
    )

Python 3.3::

    _DEFAULT_CIPHERS = 'DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2'

Options
=======

* ``SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS``: CBC IV attack countermeasure
  (CVE-2011-3389)
* ``SSL_OP_NO_SSLv2``: SSLv2 is unsafe
* ``SSL_OP_NO_SSLv3``: SSLv3 is unsafe
* ``SSL_OP_NO_COMPRESSION``: `CRIME
  <https://en.wikipedia.org/wiki/CRIME_(security_exploit)>`_ countermeasure
* ``SSL_OP_CIPHER_SERVER_PREFERENCE``
* ``SSL_OP_SINGLE_DH_USE``
* ``SSL_OP_SINGLE_ECDH_USE``

Python 3.7::

    /* Defaults */
        options = SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
        if (proto_version != PY_SSL_VERSION_SSL2)
            options |= SSL_OP_NO_SSLv2;
        if (proto_version != PY_SSL_VERSION_SSL3)
            options |= SSL_OP_NO_SSLv3;
        /* Minimal security flags for server and client side context.
         * Client sockets ignore server-side parameters. */
    #ifdef SSL_OP_NO_COMPRESSION
        options |= SSL_OP_NO_COMPRESSION;
    #endif
    #ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
        options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
    #endif
    #ifdef SSL_OP_SINGLE_DH_USE
        options |= SSL_OP_SINGLE_DH_USE;
    #endif
    #ifdef SSL_OP_SINGLE_ECDH_USE
        options |= SSL_OP_SINGLE_ECDH_USE;
    #endif
        SSL_CTX_set_options(self->ctx, options);

CA store
========

``SSLContext.load_default_certs()`` new in Python 3.4.

* Windows: ``ssl.enum_certificates(store_name)``, new in Python 3.4.
  Use `CertOpenStore()
  <https://msdn.microsoft.com/en-us/library/windows/desktop/aa376559(v=vs.85).aspx>`_
  and ``CertEnumCertificatesInStore()`` functions.
* Linux: xxx
* macOS: xxx

SSLContext
==========

New in Python 3.2.

CRLs
====

* ``SSLContext.verify_flags``: New in Python 3.4
* ``SSLContext.load_verify_locations()``: This method can also load
  certification revocation lists (CRLs) in PEM or DER format. New in Python 3.5.
* ``ssl.enum_crls(store_name)``: new in Python 3.4, specific to Windows

Validate TLS certificates
=========================

* `Python decides for certificate validation
  <https://lwn.net/Articles/611243/>`_ (September, 2014)
* CVE-2014-9365
* Python 2.7.9 (2014-12-10)
* Python 3.4.3 (2015-02-23)
* `PEP 476: Enabling certificate verification by default for stdlib http
  clients <https://www.python.org/dev/peps/pep-0476/>`_: Python 3.4.3, 3.5
* `PEP 466 <https://www.python.org/dev/peps/pep-0466/>`_: Python 2.7.9
* Version matrix?

  - HTTP
  - SMTP
  - FTP
  - IMAP
  - POP3
  - XML-RPC
  - NNTP

TLS versions
============

* SSLv2 now black listed
* SSLv3 now black listed

OpenSSL versions
================

Python bundled OpenSSL on Windows. Official Windows installer:

* Python 2.7.13, 3.5.3 and 3.6.0: openssl-1.0.2j
* Python 2.7.12, 3.5.2: openssl-1.0.2h
* Python 2.7.11, 3.4.4, 3.5.0, 3.5.1: openssl-1.0.2d
* Python 2.7.10: openssl-1.0.2a
* Python 2.7.9: openssl-1.0.1j
* Python 3.3.5: openssl-1.0.1e

Windows: see `PCbuild/get_externals.bat
<https://github.com/python/cpython/blob/master/PCbuild/get_externals.bat>`_
(or PCbuild/readme.txt in older versions).

OpenSSL also bundled on macOS?

Links
=====

* `The future of the Python ssl module
  <https://lwn.net/Articles/688974/>`_ (June, 2016 )
* `cryptography  (cryptography.io) <https://cryptography.io/>`_: Python library
  which exposes cryptographic recipes and primitives
* `pyOpenSSL <https://pypi.python.org/pypi/pyOpenSSL>`_
* `M2Crypto <https://pypi.python.org/pypi/M2Crypto>`_
* `urllib3 <https://urllib3.readthedocs.io/`>_
* `LibreSSL <http://www.libressl.org/>`_
* `borringssl <https://boringssl.googlesource.com/boringssl/>`_