#!/usr/bin/env python3

# Prepare a release:
#
#  - git pull --rebase
#  - update version in setup.py, check-python-vuln/__init__.py and doc/conf.py
#  - set release date in doc/changelog.rst
#  - git commit -a -m "prepare release x.y"
#  - Remove untracked files/dirs: git clean -fdx
#  - run tests: tox
#  - git push
#  - check Travis CI status:
#    https://travis-ci.org/vstinner/check-python-vuln
#
# Release a new version:
#
#  - git tag VERSION
#  - git push --tags
#  - Remove untracked files/dirs: git clean -fdx
#  - python3 setup.py sdist bdist_wheel
#  - twine upload dist/*
#
# After the release:
#
#  - set version to n+1
#  - git commit -a -m "post-release"
#  - git push

VERSION = '0.0'

DESCRIPTION = 'Check Python vulnerabilities'
CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Natural Language :: English',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
]


# put most of the code inside main() to be able to import setup.py in
# test_tools.py, to ensure that VERSION is the same than
# check-python-vuln.__version__.
def main():
    from setuptools import setup

    with open('README.rst') as fp:
        long_description = fp.read().strip()

    options = {
        'name': 'check-python-vuln',
        'version': VERSION,
        'license': 'MIT license',
        'description': DESCRIPTION,
        'long_description': long_description,
        'url': 'https://github.com/vstinner/python-security',
        'author': 'Victor Stinner',
        'author_email': 'vstinner@redhat.com',
        'classifiers': CLASSIFIERS,
        'packages': ['check_python_vuln'],
        # FIXME
        #'entry_points': {
        #    'console_scripts': ['check-python-vuln=check_python_vuln.__main__:main']
        #}
    }
    setup(**options)


if __name__ == '__main__':
    main()
