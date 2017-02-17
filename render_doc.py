#!/usr/bin/env python3
import argparse
import subprocess
import sys
import tabulate
import yaml


def parse_date(text):
    return text

def format_date(date):
    return date


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

    def url(self):
        return 'https://github.com/python/cpython/commit/' + self.commit

    @property
    def short(self):
        return self.commit[:7]


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
            parts = tag.split(".")
            key = (int(parts[0]), int(parts[1]))
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
    def __init__(self, commit, commit_date):
        self.commit = commit
        self.commit_date = commit_date
        self.python_versions = []


class PythonVersion:
    def __init__(self, version, date):
        self.version = version
        self.date = date


class Vulnerability:
    def __init__(self, app, data):
        self.name = data['name']
        self.disclosure = parse_date(data['disclosure'])
        self.description = data['description'].rstrip()
        self.links = data.get('links')
        self.fixed_in = []

        fixes = []
        commits = data['fixed-in']
        for commit in commits:
            commit_date = app.commit_dates.get_commit_date(commit)
            versions = app.commit_tags.get_tags(commit)

            fix = Fix(commit, commit_date)
            for version in versions:
                version_date = app.python_releases.get_date(version)
                pyver = PythonVersion(version, version_date)
                fix.python_versions.append(pyver)
            fixes.append(fix)

        if 0:
            date = app.commit_dates.get_commit_date(commit)
            # FIXME: use versions
            commit = Commit(commit, date)
            self.fixed_in.append((version, commit))

        self.fixed_in.sort()


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
                version = parts[0]
                date = parts[1]
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

        vulnerabilities.sort(key=Vulnerability.sort_key)

        headers = ['Bug', 'Disclosure', 'Fixed In', 'Vulnerable', 'Comment']
        table = []
        sections = []


        for vuln in vulnerabilities:
            fixed_in = ['{}: {}'.format(version, commit.short)
                        for version, commit in vuln.fixed_in]
            # FIXME: one per line, support multilines
            fixed_in = ', '.join(fixed_in)

            name = "`%s`_" % vuln.name
            disclosure = format_date(vuln.disclosure)
            vulnerable = 'XXX'
            # FIXME: support multilines
            description = vuln.description.replace("\n", " ")

            row = [name, disclosure, fixed_in, vulnerable, description]
            table.append(row)

        with open(filename, 'w', encoding='utf-8') as fp:
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
                print(vuln.description, file=fp)

                if vuln.fixed_in:
                    print(file=fp)
                    print("Fixed In:", file=fp)
                    for version, commit in vuln.fixed_in:
                        short = commit.short
                        date = format_date(commit.date)
                        url = commit.url()
                        print("* {}: {}, `commit {} <{}>`_".format(version, date, short, url),
                              file=fp)

                links = vuln.links
                if links:
                    print(file=fp)
                    print("Links:", file=fp)
                    for link in links:
                        print("* %s" % link, file=fp)

        print("{} generated".format(filename))


if __name__ == "__main__":
    filename = 'test.rst'
    date_filename = 'commit_dates.txt'
    tags_filename = 'commit_tags.txt'
    python_path = '/home/haypo/prog/python/master'

    app = RenderDoc(python_path, date_filename, tags_filename)
    app.main(filename)
