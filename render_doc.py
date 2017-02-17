#!/usr/bin/env python3
import tabulate
import yaml
import argparse

def parse_date(text):
    return text

def format_date(date):
    return date

class Commit:
    def __init__(self, commit):
        self.commit = commit

    def url(self):
        return 'https://github.com/python/cpython/commit/' + self.commit

    @property
    def short(self):
        return self.commit[:7]


class Vulnerability:
    def __init__(self, data):
        self.name = data['name']
        self.disclosure = parse_date(data['disclosure'])
        self.description = data['description'].rstrip()
        self.links = data.get('links')
        self.fixed_in = []
        for item in data['fixed-in']:
            for version, commit in item.items():
                commit = Commit(commit)
                self.fixed_in.append((version, commit))
        self.fixed_in.sort()


    @staticmethod
    def sort_key(vuln):
        return vuln.disclosure


def main(filename):
    vulnerabilities = []
    with open("vulnerabilities.yml", encoding="utf-8") as fp:
        for data in yaml.load(fp):
            vuln = Vulnerability(data)
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

        vulnerable = 'XXX'
        # FIXME: support multilines
        description = vuln.description.replace("\n", " ")

        name = "`%s`_" % vuln.name

        row = [name, format_date(vuln.disclosure), fixed_in, vulnerable, description]
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
                    url = commit.url()
                    print("* {}: `commit {} <{}>`_".format(version, short, url),
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
    main(filename)
