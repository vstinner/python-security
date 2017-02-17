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


class Commit:
    def __init__(self, commit, date):
        self.commit = commit
        self.date = date

    def url(self):
        return 'https://github.com/python/cpython/commit/' + self.commit

    @property
    def short(self):
        return self.commit[:7]


class GitRepository:
    def __init__(self, date_filename):
        self.date_filename = date_filename
        # commit (sha1) => date
        self.date_cache = {}
        self.read_date_cache()
        self.directory = None

    def read_date_cache(self):
        try:
            fp = open(self.date_filename, encoding="utf-8")
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
                self.date_cache[commit] = date

    def write_date_cache(self):
        commits = list(self.date_cache.items())
        commits.sort()

        with open(self.date_filename, "w", encoding="utf-8") as fp:
            for commit, date in commits:
                print("%s: %s" % (commit, date), file=fp)

    def _get_commit_date(self, commit):
        cmd = ["git", "show", commit]
        proc = subprocess.run(cmd,
                              stdout=subprocess.PIPE,
                              universal_newlines=True,
                              cwd=self.directory)
        if proc.returncode:
            print("Command failed with exit code %s"
                  % (' '.join(cmd), proc.returncode))
            sys.exit(proc.returncode)

        for line in proc.stdout.splitlines():
            if not line.startswith('Date:'):
                continue
            return line[5:].strip()

        print("ERROR: failed to get commit date")
        print(proc.stdout)
        sys.exit(1)

    def get_commit_date(self, commit):
        if commit in self.date_cache:
            return self.date_cache[commit]

        date = self._get_commit_date(commit)
        self.date_cache[commit] = date
        self.write_date_cache()
        return date


class Vulnerability:
    def __init__(self, repo, data):
        self.name = data['name']
        self.disclosure = parse_date(data['disclosure'])
        self.description = data['description'].rstrip()
        self.links = data.get('links')
        self.fixed_in = []
        for item in data['fixed-in']:
            for version, commit in item.items():
                date = repo.get_commit_date(commit)
                commit = Commit(commit, date)
                self.fixed_in.append((version, commit))
        self.fixed_in.sort()


    @staticmethod
    def sort_key(vuln):
        return vuln.disclosure


class RenderDoc:
    def __init__(self):
        self.repo = GitRepository('commit_dates.txt')

    def main(self, filename, python_path):
        self.repo.directory = python_path

        vulnerabilities = []
        with open("vulnerabilities.yml", encoding="utf-8") as fp:
            for data in yaml.load(fp):
                vuln = Vulnerability(self.repo, data)
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
    python_path = '/home/haypo/prog/python/master'
    RenderDoc().main(filename, python_path)
