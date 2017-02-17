#!/usr/bin/env python3
import tabulate
import yaml
import argparse

def parse_date(text):
    return text

def format_date(date):
    return date

def sort_key(vuln):
    return parse_date(vuln['disclosure'])

def main(filename):
    with open("vulnerabilities.yml", encoding="utf-8") as fp:
        vulnerabilities = yaml.load(fp)

    headers = ['Bug', 'Disclosure', 'Fixed In', 'Vulnerable', 'Comment']
    table = []
    sections = []

    vulnerabilities.sort(key=sort_key)

    for vuln in vulnerabilities:
        name = vuln['name']
        disclosure = parse_date(vuln['disclosure'])
        description = vuln['description']

        fixed_in = []
        for item in vuln['fixed-in']:
            for version, commit in item.items():
                fixed_in.append('{}: {}'.format(version, commit))
        # FIXME: one per line, support multilines
        fixed_in = ', '.join(fixed_in)

        vulnerable = 'XXX'
        # FIXME: support multilines
        description = description.replace("\n", " ")

        name = "`%s`_" % name

        row = [name, format_date(disclosure), fixed_in, vulnerable, description]
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

            name = vuln['name']

            print(name, file=fp)
            print("=" * len(name), file=fp)
            print(file=fp)
            print(vuln['description'].rstrip(), file=fp)

            links = vuln.get('links')
            if links:
                print(file=fp)
                print("Links:", file=fp)
                for link in links:
                    print("* %s" % link, file=fp)

    print("{} generated".format(filename))


if __name__ == "__main__":
    filename = 'test.rst'
    main(filename)
