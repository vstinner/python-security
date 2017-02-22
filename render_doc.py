#!/usr/bin/env python3
import argparse
import datetime
import re
import subprocess
import sys
import tabulate
import yaml


CVE_REGEX = re.compile('(?<!`)CVE-[0-9]+-[0-9]+')
CVE_URL = 'http://www.cvedetails.com/cve/%s/'


def parse_date(text):
    if isinstance(text, datetime.date):
        return text

    try:
        dt = datetime.datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        # Mon Apr 18 03:45:18 2016 +0000
        dt = datetime.datetime.strptime(text, "%a %b %d %H:%M:%S %Y %z")
        dt = (dt - dt.utcoffset()).replace(tzinfo=datetime.timezone.utc)
    return dt.date()


def format_date(date):
    return date.strftime("%Y-%m-%d")


def run(cmd, cwd):
    proc = subprocess.run(cmd,
                          stdout=subprocess.PIPE,
                          universal_newlines=True,
                          cwd=cwd)
    if proc.returncode:
        print("Command failed with exit code %s"
              % (' '.join(cmd), proc.returncode))
        sys.exit(proc.returncode)
    return proc


def commit_url(commit):
    return 'https://github.com/python/cpython/commit/' + commit

def short_commit(commit):
    return commit[:7]


class CommitDates:
    def __init__(self, python_path, cache_filename):
        self.python_path = python_path
        self.cache_filename = cache_filename
        # commit (sha1) => date
        self.cache = {}
        self.read_cache()

    def read_cache(self):
        try:
            fp = open(self.cache_filename, encoding="utf-8")
        except FileNotFoundError:
            return

        with fp:
            for line in fp:
                line = line.rstrip()
                if not line:
                    continue
                commit, date = line.split(':', 1)
                commit = commit.strip()
                date = date.strip()
                self.cache[commit] = date

    def write_cache(self):
        commits = list(self.cache.items())
        commits.sort()

        with open(self.cache_filename, "w", encoding="utf-8") as fp:
            for commit, date in commits:
                print("%s: %s" % (commit, date), file=fp)

    def _get_commit_date(self, commit):
        print("Get %s date" % commit)

        cmd = ["git", "show", commit]
        proc = run(cmd, self.python_path)
        for line in proc.stdout.splitlines():
            if not line.startswith('Date:'):
                continue
            return line[5:].strip()

        print("ERROR: failed to get commit date")
        print(proc.stdout)
        sys.exit(1)

    def get_commit_date(self, commit):
        if commit in self.cache:
            date = self.cache[commit]
            return parse_date(date)

        date = self._get_commit_date(commit)
        self.cache[commit] = date
        self.write_cache()
        return parse_date(date)


def version_info(version):
    info = tuple(map(int, version.split('.')))
    if len(info) == 2:
        info += (0,)
    return info


def python_major_version(version):
    return version_info(version)[:2]


class CommitTags:
    def __init__(self, python_path, cache_filename):
        self.python_path = python_path
        self.cache_filename = cache_filename
        # commit (sha1) => tag list
        # tag list: list of (version: tuple, tag: str)
        self.cache = {}
        self.read_cache()

    def read_cache(self):
        try:
            fp = open(self.cache_filename, encoding="utf-8")
        except FileNotFoundError:
            return

        with fp:
            commit = None
            tags = []
            for line in fp:
                line = line.rstrip()
                if not line:
                    continue
                if line.startswith(' ') and commit:
                    tag = line[1:]
                    tags.append(tag)
                else:
                    if commit and tags:
                        self.cache[commit] = tags
                    commit = line
                    tags = []

            if commit and tags:
                self.cache[commit] = tags

    def write_cache(self):
        with open(self.cache_filename, "w", encoding="utf-8") as fp:
            items = sorted(self.cache.items())
            for commit, tags in items:
                print(commit, file=fp)
                for tag in tags:
                    print(" %s" % tag, file=fp)

    def _get_tags(self, commit, ignore_python3):
        print("Get %s tags" % commit)

        cmd = ["git", "tag", "--contains", commit]
        proc = run(cmd, self.python_path)

        tags = []
        for line in proc.stdout.splitlines():
            line = line.rstrip()
            if not line.startswith("v"):
                continue
            tag = line[1:]
            # strip alpha part,
            # 'c' is needed for v2.5.6c1
            for suffix in ('a', 'b', 'rc', 'c'):
                if suffix in tag:
                    tag = tag.partition(suffix)[0]
            tag = version_info(tag)
            if ignore_python3 and tag >= (3,):
                continue
            tags.append(tag)

        tags.sort()
        tags2 = []
        seen = set()
        major = None
        for tag_info in tags:
            key = tag_info[:2]
            if key in seen:
                continue
            seen.add(key)
            if tag_info[0] == major:
                continue
            if tag_info[2] == 0:
                major = tag_info[0]
            tag = '.'.join(map(str, tag_info))
            tags2.append(tag)
        tags = tags2

        self.cache[commit] = tags
        self.write_cache()
        return tags

    def get_tags(self, commit, ignore_python3=False):
        if commit in self.cache:
            return self.cache[commit]

        tags = self._get_tags(commit, ignore_python3)
        self.cache[commit] = tags
        return tags


class Fix:
    def __init__(self, commit, commit_date, python_version, release_date):
        self.commit = commit
        self.commit_date = commit_date
        self.python_version = python_version
        self.release_date = release_date

    @staticmethod
    def sort_key(fix):
        return version_info(fix.python_version)


class Vulnerability:
    def __init__(self, app, data):
        self.name = data.pop('name')
        disclosure = data.pop('disclosure')
        if isinstance(disclosure, str):
            disclosure_date, _, comment = disclosure.partition('(')
            disclosure_date = disclosure_date.strip()
            if comment:
                if not comment.endswith(')'):
                    raise ValueError("disclosure comment must be written in (...)")
                comment = comment[:-1]
            else:
                comment = None
        else:
            disclosure_date = disclosure
            comment = None
        self.disclosure_date = parse_date(disclosure_date)
        self.disclosure_comment = comment
        self.summary = data.pop('summary').strip()
        self.description = data.pop('description').strip()
        self.links = data.pop('links', None)
        self.cvss_score = data.pop('cvss-score', None)
        self.redhat_impact = data.pop('redhat-impact', None)
        self.reported_by = data.pop('reported-by', None)
        if self.reported_by is not None:
            self.reported_by = self.reported_by.strip()

        cves = set()
        for text in (self.name, self.description):
            for cve in CVE_REGEX.findall(text):
                cves.add(cve)

        for cve in sorted(cves):
            url = CVE_URL % cve
            if not self.links:
                self.links = []
            self.links.append(url)

        self.find_fixes(data)

        if data:
            raise Exception("Vulnerability %r has unknown keys: %s"
                            % (self.name, ', '.join(sorted(data))))

    def find_fixes(self, data):
        fixes = []
        ignore_python3 = data.pop('ignore-python3', None)
        commits = data.pop('fixed-in')
        for commit in commits:
            commit_date = app.commit_dates.get_commit_date(commit)
            versions = app.commit_tags.get_tags(commit,
                                                ignore_python3=ignore_python3)
            for version in versions:
                release_date = app.python_releases.get_date(version)
                fix = Fix(commit, commit_date, version, release_date)
                fixes.append(fix)

        fixes.sort(key=Fix.sort_key)

        self.fixes = []
        seen = set()
        major = None
        for fix in fixes:
            pyver_info = version_info(fix.python_version)
            key = python_major_version(fix.python_version)
            if key in seen:
                continue
            seen.add(key)
            if pyver_info[0] == major:
                continue
            if pyver_info[2] == 0:
                major = pyver_info[0]
            self.fixes.append(fix)

    @staticmethod
    def sort_key(vuln):
        date = datetime.date.min - vuln.disclosure_date
        return (date, vuln.name, vuln.summary)


class PythonReleases:
    def __init__(self):
        self.dates = {}
        with open("python_releases.txt", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":", 1)
                version = parts[0].strip()
                date = parts[1].strip()
                date = parse_date(date)
                self.dates[version] = date

    def get_date(self, version):
        if version.count('.') == 1:
            version += '.0'
        try:
            return self.dates[version]
        except KeyError:
            raise KeyError("missing release date of Python %s" % version)


class RenderDoc:
    def __init__(self, python_path, date_filename, tags_filename):
        self.commit_dates = CommitDates(python_path, date_filename)
        self.commit_tags = CommitTags(python_path, tags_filename)
        self.python_releases = PythonReleases()

    def main(self, filename):
        vulnerabilities = []
        with open("vulnerabilities.yml", encoding="utf-8") as fp:
            for data in yaml.load(fp):
                vuln = Vulnerability(self, data)
                vulnerabilities.append(vuln)

        vulnerabilities.sort(key=Vulnerability.sort_key)

        headers = ['Vulnerability', 'Summary', 'Disclosure', 'Score', 'Fixed In']
        table = []
        sections = []


        for vuln in vulnerabilities:
            fixes = [fix.python_version for fix in vuln.fixes]
            fixes = ', '.join(fixes)

            name = "`%s`_" % vuln.name
            disclosure = format_date(vuln.disclosure_date)
            score = vuln.cvss_score or vuln.redhat_impact or '?'

            row = [name, vuln.summary, disclosure, score, fixes]
            table.append(row)

        with open(filename, 'w', encoding='utf-8') as fp:
            title = 'Security vulnerabilities'
            print("+" * len(title), file=fp)
            print(title, file=fp)
            print("+" * len(title), file=fp)
            print(file=fp)

            print(tabulate.tabulate(table, headers, tablefmt="grid"), file=fp)
            print(file=fp)
            print("Total: %s vulnerabilities" % len(table), file=fp)
            print(file=fp)
            print("* Vulnerabilities sorted by the Disclosure column", file=fp)
            print("* Disclosure: Disclosure date, first time that the vulnerability was public", file=fp)
            print("* `CVSS Score <https://nvd.nist.gov/cvss.cfm>`_", file=fp)
            print("* `Red Hat impact <https://access.redhat.com/security/updates/classification/>`_", file=fp)

            for vuln in vulnerabilities:
                print(file=fp)
                print(file=fp)

                name = vuln.name

                print(name, file=fp)
                print("=" * len(name), file=fp)
                print(file=fp)
                print(vuln.description, file=fp)

                disclosure = format_date(vuln.disclosure_date)
                if vuln.disclosure_comment:
                    disclosure = '%s (%s)' % (disclosure, vuln.disclosure_comment)
                print(file=fp)

                print("Information:", file=fp)
                print(file=fp)
                print("* Disclosure date: {}".format(disclosure), file=fp)
                if vuln.reported_by:
                    print("* Reported by: {}".format(vuln.reported_by), file=fp)
                if vuln.cvss_score:
                    print("* `CVSS Score`_: {}".format(vuln.cvss_score), file=fp)
                if vuln.redhat_impact:
                    print("* `Red Hat impact`_: {}".format(vuln.redhat_impact), file=fp)

                if vuln.fixes:
                    print(file=fp)
                    print("Fixed In:", file=fp)
                    print(file=fp)
                    for index, fix in enumerate(vuln.fixes):
                        short = short_commit(fix.commit)
                        date = format_date(fix.release_date)
                        url = commit_url(fix.commit)
                        days = (fix.release_date - vuln.disclosure_date).days
                        commit_date = format_date(fix.commit_date)
                        commit_days = (fix.commit_date - vuln.disclosure_date).days
                        pyver_info = version_info(fix.python_version)

                        version = fix.python_version
                        commit = "`commit {} <{}>`_".format(short, url)

                        # Don't show the date/days fort 3.x.0 releases, except
                        # if it's the first (and so the only) version having
                        # the fix (ex: CVE-2013-7040)
                        if pyver_info[2] != 0 or index == 0:
                            date = "{} ({} days)".format(date, days)
                            commit = "{} ({}, {} days)".format(commit, commit_date, commit_days)
                        else:
                            commit = "{} ({})".format(commit, commit_date)
                        print("* {}: {}, {}".format(version, date, commit),
                              file=fp)

                links = vuln.links
                if links:
                    print(file=fp)
                    print("Links:", file=fp)
                    print(file=fp)
                    for link in links:
                        print("* %s" % link, file=fp)

        print("{} generated".format(filename))


if __name__ == "__main__":
    filename = 'vulnerabilities.rst'
    date_filename = 'commit_dates.txt'
    tags_filename = 'commit_tags.txt'
    python_path = '/home/haypo/prog/python/master'

    app = RenderDoc(python_path, date_filename, tags_filename)
    app.main(filename)
