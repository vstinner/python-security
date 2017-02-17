#!/usr/bin/env python3
import argparse
import datetime
import re
import subprocess
import sys
import tabulate
import yaml


def parse_date(text):
    if isinstance(text, datetime.date):
        return text

    try:
        dt = datetime.datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        # Mon Apr 18 03:45:18 2016 +0000
        dt = datetime.datetime.strptime(text, "%a %b %d %H:%M:%S %Y %z")
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


# FIXME: remove this class?
class Commit:
    def __init__(self, commit, date):
        self.commit = commit
        self.date = date

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
                date = parse_date(date)
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
            return self.cache[commit]

        date = self._get_commit_date(commit)
        self.cache[commit] = date
        self.write_cache()
        return date


def version_info(version):
    return tuple(map(int, version.split('.')))


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

    def _get_tags(self, commit):
        print("Get %s tags" % commit)

        cmd = ["git", "tag", "--contains", commit]
        proc = run(cmd, self.python_path)
        tags = {}
        for line in proc.stdout.splitlines():
            line = line.rstrip()
            if not line.startswith("v"):
                continue
            tag = line[1:]
            key = python_major_version(tag)
            if key in tags:
                continue
            tags[key] = tag

        tags = sorted(tags.items())
        tags = [tag for key, tag in tags]
        self.cache[commit] = tags
        self.write_cache()
        return tags

    def get_tags(self, commit):
        if commit in self.cache:
            return self.cache[commit]

        tags = self._get_tags(commit)
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
        return tuple(map(int, fix.python_version.split(".")))


class Vulnerability:
    def __init__(self, app, data):
        self.name = data['name']
        self.disclosure = parse_date(data['disclosure'])
        self.description = data['description'].rstrip()
        self.links = data.get('links')

        fixes = []
        commits = data['fixed-in']
        for commit in commits:
            commit_date = app.commit_dates.get_commit_date(commit)
            versions = app.commit_tags.get_tags(commit)
            for version in versions:
                release_date = app.python_releases.get_date(version)
                fix = Fix(commit, commit_date, version, release_date)
                fixes.append(fix)

        fixes.sort(key=Fix.sort_key)

        self.fixes = []
        seen = set()
        for fix in fixes:
            pyver_info = version_info(fix.python_version)
            key = python_major_version(fix.python_version)
            if key in seen:
                continue
            seen.add(key)
            if pyver_info >= (3, 0) and pyver_info[2] == 0:
                break
            self.fixes.append(fix)


    @staticmethod
    def sort_key(vuln):
        return vuln.disclosure


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
        return self.dates[version]


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

        vulnerabilities.sort(key=Vulnerability.sort_key, reverse=True)

        headers = ['Vulnerability', 'Disclosure', 'Fixed In', 'Description']
        table = []
        sections = []


        for vuln in vulnerabilities:
            fixes = [fix.python_version for fix in vuln.fixes]
            # FIXME: one per line, support multilines
            fixes = ', '.join(fixes)

            name = "`%s`_" % vuln.name
            disclosure = format_date(vuln.disclosure)
            # FIXME: support multilines
            description = vuln.description.replace("\n", " ")

            row = [name, disclosure, fixes, description]
            table.append(row)

        with open(filename, 'w', encoding='utf-8') as fp:
            title = 'Security vulnerabilities'
            print("+" * len(title), file=fp)
            print(title, file=fp)
            print("+" * len(title), file=fp)
            print(file=fp)

            title = 'Security vulnerabilities'
            print(title, file=fp)
            print("=" * len(title), file=fp)
            print(file=fp)

            print(tabulate.tabulate(table, headers, tablefmt="grid"), file=fp)

            for vuln in vulnerabilities:
                print(file=fp)
                print(file=fp)

                name = vuln.name

                print(name, file=fp)
                print("=" * len(name), file=fp)
                print(file=fp)
                print("Disclosure date: {}.".format(format_date(vuln.disclosure)), file=fp)
                print(file=fp)
                print(vuln.description, file=fp)

                if vuln.fixes:
                    print(file=fp)
                    print("Fixed In:", file=fp)
                    print(file=fp)
                    for fix in vuln.fixes:
                        short = short_commit(fix.commit)
                        date = format_date(fix.release_date)
                        url = commit_url(fix.commit)
                        days = (fix.release_date - vuln.disclosure).days
                        print("* {} ({} days): {}, `commit {} <{}>`_".format(fix.python_version, days, date, short, url),
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
