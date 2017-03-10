#!/usr/bin/env python3
import argparse
import datetime
import glob
import json
import os.path
import re
import subprocess
import sys
import urllib.request
import xmlrpc.client
import yaml


CVE_REGEX = re.compile('(?<!`)CVE-[0-9]+-[0-9]+')
CVE_URL = 'https://www.cvedetails.com/cve/%s/'
CVE_API = 'http://cve.circl.lu/api/cve/%s'
BPO_URL = 'https://bugs.python.org/issue%s'
CVSS_SCORE_URL = 'https://nvd.nist.gov/cvss.cfm'
RED_HAT_IMPACT_URL = 'https://access.redhat.com/security/updates/classification/'
# FIXME: need login+password in BUGS_API, add a configuration file?
# https://user:password@bugs.python.org/xmlrpc
BUGS_API = 'https://bugs.python.org/xmlrpc'
BUGS_DATE_REGEX = re.compile(r'<Date (.*)>')


def create_slug(name):
    slug = name.lower()
    slug = re.sub(r'[#(),]', '', slug)
    slug = re.sub(r'[ :]', '_', slug)
    slug = re.sub(r'__+', '_', slug)
    if not re.match('^[a-z0-9._-]+$', slug):
        raise ValueError("invalid slug: %r" % slug)
    return slug


def try_mkdir(path):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass


def download(url):
    response = urllib.request.urlopen(url)
    with response:
        return response.read()


def load_json(filename):
    with open(filename, encoding="utf-8") as fp:
        return json.load(fp)


def dump_json(filename, data):
    with open(filename, "w", encoding="utf-8") as fp:
        return json.dump(data, fp, sort_keys=True, indent=4)


def load_yaml(filename):
    with open(filename, encoding="utf-8") as fp:
        return yaml.load(fp, Loader=yaml.SafeLoader)


def dump_yaml(filename, data):
    with open(filename, "w", encoding="utf-8") as fp:
        return yaml.dump(data, fp, indent=4, default_flow_style=False)


def timedelta_days(delta):
    return delta.days


def parse_date(text):
    if isinstance(text, datetime.date):
        return text

    try:
        dt = datetime.datetime.strptime(text, "%Y-%m-%d")
        return dt.date()
    except ValueError:
        pass

    try:
        # Mon Apr 18 03:45:18 2016 +0000
        dt = datetime.datetime.strptime(text, "%a %b %d %H:%M:%S %Y %z")
        dt = (dt - dt.utcoffset()).replace(tzinfo=datetime.timezone.utc)
        return dt.date()
    except ValueError:
        pass

    try:
        # CVE date: 2016-09-02T10:59:00.127-04:00
        if len(text) == 29 and text.count('.') == 1:
            text2 = re.sub(r'\.[0-9]{3}', '', text)
            def replace_timezone(regs):
                text = regs.group(0)
                return text[:2] + text[3:]
            text2 = re.sub(r'[0-9]{2}:[0-9]{2}$', replace_timezone, text2)

            dt = datetime.datetime.strptime(text2, "%Y-%m-%dT%H:%M:%S%z")
            dt = (dt - dt.utcoffset()).replace(tzinfo=datetime.timezone.utc)
            return dt.date()
    except ValueError:
        pass

    raise ValueError("unable to parse date: %r" % text)


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


class DateComment:
    def __init__(self, date, comment):
        self.date = date
        self.comment = comment

    def __str__(self):
        text = format_date(self.date)
        if self.comment:
            text = '%s (%s)' % (text, self.comment)
        return text


def parse_date_comment(date):
    comment = None
    if isinstance(date, datetime.date):
        return DateComment(date, comment)

    # date is a string
    date, _, comment = date.partition('(')
    date = date.strip()
    if comment:
        if not comment.endswith(')'):
            raise ValueError("date comment must be written in (...)")
        comment = comment[:-1].strip()
    date = parse_date(date)
    return DateComment(date, comment)


class PythonBugs:
    def __init__(self, filename):
        self.filename = filename
        self.bugs = {}
        self.load()

    def load(self):
        try:
            bugs = load_yaml(self.filename)
        except FileNotFoundError:
            return
        if not bugs:
            return

        for number, bug in bugs.items():
            self.bugs[number] = bug

    def download(self, number):
        try:
            return self.bugs[number]
        except KeyError:
            pass

        print("Download issue #%s" % number)

        bug = {}
        server = xmlrpc.client.ServerProxy(BUGS_API, allow_none=True)
        with server:
            issue = server.display('issue%s' % number)
            bug['title'] = issue['title']

            msg = issue['messages'][0]
            msg = server.display('msg%s' % msg)
            match = BUGS_DATE_REGEX.match(msg['date'])
            if not match:
                raise Exception("unable to parse bug msg date: %r" % msg['date'])
            bug['date'] = match.group(1)

            user = server.display('user%s' % msg['author'], 'username', 'realname')
            bug['author'] = user['realname'] or user['username']

        self.bugs[number] = bug
        self.dump()
        return bug

    def get_bug(self, number):
        bug = self.download(number)

        date = bug['date']
        date = datetime.datetime.strptime(date[:11], "%Y-%m-%d.").date()
        return PythonBug(number, bug['author'], bug['title'], date)

    def dump(self):
        data = self.bugs
        dump_yaml(self.filename, data)


class PythonBug:
    def __init__(self, number, author, title, date):
        self.number = number
        self.author = author
        self.date = date
        self.title = title

    def get_url(self):
        return BPO_URL % self.number


class CVERegistry:
    def __init__(self, path):
        self.path = path
        self.cves = {}
        try_mkdir(self.path)
        self.load()

    def load_cve(self, number, filename):
        if os.path.getsize(filename) == 0:
            # special case: empty file used as a marker to avoid
            # downloading again, use None
            cve = None
        else:
            cve = load_json(filename)
        self.cves[number] = cve

    def load(self):
        for filename in glob.glob(os.path.join(self.path, '*.json')):
            number = os.path.basename(filename[:-5])
            if not number.startswith("CVE-"):
                continue
            self.load_cve(number, filename)

    def dump(self):
        for number, cve in self.cves.items():
            filename = os.path.join(self.path, number + '.json')
            if cve is not None:
                dump_json(filename, cve)
            else:
                # create empty file
                fp = open(filename, "wb")
                fp.close()

    def get_cve(self, number):
        try:
            cve = self.cves[number]
        except KeyError:
            url = CVE_API % number
            print("Download %s" % url)

            data = download(url)
            data = data.decode('utf-8')
            cve = json.loads(data)
            if not cve:
                cve = None
            self.cves[number] = cve
            self.dump()

        if cve is None:
            return None
        return CVE(number, cve)


class CVE:
    def __init__(self, number, data):
        self.number = number
        try:
            self.published = parse_date(data['Published'])
            self.summary = data['summary']
            self.cvss = data['cvss']
        except Exception:
            raise Exception("failed to parse %s" % self.number)


class Vulnerability:
    def __init__(self, app, data):
        self.name = data.pop('name')
        try:
            self.parse(app, data)
        except KeyError as exc:
            raise Exception("failed to parse %r: missing key %s" % (self.name, exc))
        except Exception as exc:
            raise Exception("failed to parse %r: %s" % (self.name, exc))
        self.slug = create_slug(self.name)

    def parse(self, app, data):
        bpo = int(data.pop('bpo', 0))
        if bpo:
            self.python_bug = app.bugs.get_bug(bpo)
        else:
            self.python_bug = None
        disclosure = data.pop('disclosure', None)
        if disclosure:
            self.disclosure = parse_date_comment(disclosure)
        elif self.python_bug:
            self.disclosure = None
        else:
            raise Exception("bug has no bpo no disclosure")
        reported_at = data.pop('reported-at', None)
        if reported_at is not None:
            self.reported_at = parse_date_comment(reported_at)
        else:
            self.reported_at = None
        self.description = data.pop('description').strip()
        self.links = data.pop('links', None)
        if not self.links:
            self.links = []
        self.redhat_impact = data.pop('redhat-impact', None)

        reported_by = data.pop('reported-by', None)
        if reported_by is not None:
            self.reported_by = reported_by.strip()
            if not self.reported_by:
                raise Exception("empty reported-by")
        elif self.python_bug:
            self.reported_by = None
        else:
            raise Exception("no reported-by nor bpo")

        # CVE
        cves = set()

        cve = data.pop('cve', None)
        if cve:
            self.name = '%s: %s' % (cve, self.name)
            # get_cve() can return None
            self.cve = app.cves.get_cve(cve)
            if self.cve is None:
                # Add a link if there is no CVE detail
                cves.add(cve)
        else:
            self.cve = None

        for text in self.description:
            for cve in CVE_REGEX.findall(text):
                cves.add(cve)

        for cve in sorted(cves):
            url = CVE_URL % cve
            self.links.append(url)

        self.find_fixes(app, data)

        if data:
            raise Exception("Vulnerability %r has unknown keys: %s"
                            % (self.name, ', '.join(sorted(data))))

    def find_fixes(self, app, data):
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

    def get_disclosure_date(self):
        if self.disclosure:
            return self.disclosure.date
        else:
            return self.python_bug.date

    @staticmethod
    def sort_key(vuln):
        date = datetime.date.min - vuln.get_disclosure_date()
        return (date, vuln.name)


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


def render_title(fp, title, line='='):
    print(title, file=fp)
    print(line * len(title), file=fp)
    print(file=fp)


def render_timeline(fp, vuln):
    render_title(fp, "Timeline", "-")

    day0 = vuln.get_disclosure_date()

    dates = []

    if vuln.disclosure:
        text = "Disclosure date"
        if vuln.disclosure.comment:
            text = '%s (%s)' % (text, vuln.disclosure.comment)
        dates.append((vuln.disclosure.date, False, text))

    if vuln.python_bug:
        bug = vuln.python_bug
        text = ("`Python issue #%s <%s>`_ reported by %s"
                % (bug.number, bug.get_url(), bug.author))
        dates.append((bug.date, bool(vuln.disclosure), text))

    cve = vuln.cve
    if cve:
        text = "%s published" % cve.number
        dates.append((cve.published, True, text))

    if vuln.reported_at:
        text = "Reported"
        if vuln.reported_at.comment:
            text = '%s (%s)' % (text, vuln.reported_at.comment)
        dates.append((vuln.reported_at.date, True, text))

    commit_seen = set()
    for fix in vuln.fixes:
        if fix.commit in commit_seen:
            continue
        commit_seen.add(fix.commit)

        short = short_commit(fix.commit)
        url = commit_url(fix.commit)
        text = "`commit {} <{}>`_".format(short, url)

        dates.append((fix.commit_date, True, text))

    for index, fix in enumerate(vuln.fixes):
        pyver_info = version_info(fix.python_version)
        # Don't show the date/days fort 3.x.0 releases, except
        # if it's the first (and so the only) version having
        # the fix (ex: CVE-2013-7040)
        show_days = (pyver_info[2] != 0 or index == 0)

        text = "Python %s released" % fix.python_version
        dates.append((fix.release_date, show_days, text))

    dates.sort()

    print("Timeline using the disclosure date **%s** as reference:"
          % (format_date(day0)), file=fp)
    print(file=fp)

    for date, show_days, text in dates:
        days = timedelta_days(date - day0)
        date = format_date(date)
        if show_days:
            date = "%s (**%+i days**)" % (date, days)
        print("* %s: %s" % (date, text), file=fp)
    print(file=fp)


def render_info(fp, vuln):
    if vuln.disclosure:
        date = vuln.disclosure.date
        comment = vuln.disclosure.comment
    else:
        date = vuln.python_bug.date
        comment = "Python issue #%s reported" % vuln.python_bug.number

    text = "**%s**" % format_date(date)
    if comment:
        text = "%s (%s)" % (text, comment)
    print("* Disclosure date: %s" % text, file=fp)

    if vuln.reported_at:
        print("* Reported at: {}".format(vuln.reported_at), file=fp)
    if vuln.reported_by:
        print("* Reported by: {}".format(vuln.reported_by), file=fp)
    if vuln.redhat_impact:
        print("* `Red Hat impact <%s>`_: %s" % (RED_HAT_IMPACT_URL, vuln.redhat_impact), file=fp)
    print(file=fp)


def render_python_bug(fp, bug):
    if not bug:
        return

    render_title(fp, "Python issue", "-")

    text = bug.title
    if not text.endswith('.'):
        text += '.'
    print(text, file=fp)
    print(file=fp)
    print("* Python issue: `issue #%s <%s>`_" % (bug.number, bug.get_url()), file=fp)
    print("* Creation date: %s" % format_date(bug.date), file=fp)
    print("* Reporter: %s" % bug.author, file=fp)
    print(file=fp)


def render_cve(fp, cve):
    if not cve:
        return

    render_title(fp, cve.number, "-")

    print(cve.summary, file=fp)
    print(file=fp)

    url = CVE_URL % cve.number
    print("* CVE ID: `%s <%s>`_" % (cve.number, url), file=fp)
    print("* Published: %s" % format_date(cve.published), file=fp)
    print("* `CVSS Score <%s>`_: %s" % (CVSS_SCORE_URL, cve.cvss), file=fp)
    print(file=fp)


def render_fixes(fp, fixes):
    if not fixes:
        return

    render_title(fp, "Fixed In", "-")

    for index, fix in enumerate(fixes):
        short = short_commit(fix.commit)
        date = format_date(fix.release_date)
        url = commit_url(fix.commit)
        commit_date = format_date(fix.commit_date)

        print("* Python **{}** ({}) fixed by `commit {} <{}>`_ ({})".format(fix.python_version, date, short, url, commit_date),
              file=fp)
    print(file=fp)


def render_links(fp, links):
    if not links:
        return

    render_title(fp, "Links", "-")

    for link in links:
        print("* %s" % link, file=fp)
    print(file=fp)


def render_vuln(filename, vuln):
    with open(filename, "w", encoding="utf-8") as fp:
        print(".. _%s:" % vuln.slug, file=fp)
        print(file=fp)

        render_title(fp, vuln.name, '=')

        print(vuln.description, file=fp)
        print(file=fp)
        render_info(fp, vuln)

        render_fixes(fp, vuln.fixes)
        render_python_bug(fp, vuln.python_bug)
        render_cve(fp, vuln.cve)
        render_timeline(fp, vuln)
        render_links(fp, vuln.links)


def render_filenames(fp, filenames):
    print("Table of Contents:", file=fp)
    print(file=fp)
    print(".. toctree::", file=fp)
    print("   :maxdepth: 2", file=fp)
    print(file=fp)
    for filename in filenames:
        name = os.path.splitext(filename)[0]
        print("   %s" % name, file=fp)
    print(file=fp)


def render_table(fp, vulnerabilities):
    headers = ['Vulnerability', 'Disclosure', 'Score', 'Fixed In']
    table = []
    sections = []

    for vuln in vulnerabilities:
        fixes = ['| ' + fix.python_version for fix in vuln.fixes]

        name = ":ref:`%s <%s>`" % (vuln.name, vuln.slug)
        disclosure = format_date(vuln.get_disclosure_date())
        if vuln.cve:
            score = str(vuln.cve.cvss)
        else:
            score = vuln.redhat_impact or '?'

        row = [name, disclosure, score, fixes]
        table.append(row)

    widths = [len(header) for header in headers]
    for row in table:
        for column, cell in enumerate(row):
            if isinstance(cell, str):
                cell_len = len(cell)
            else:
                cell_len = max(len(subcell) for subcell in cell)
            widths[column] = max(widths[column], cell_len)

    title = 'Security vulnerabilities'
    print("+" * len(title), file=fp)
    print(title, file=fp)
    print("+" * len(title), file=fp)
    print(file=fp)

    def table_line(char='-'):
        parts = ['']
        for width in widths:
            parts.append(char * (width + 2))
        parts.append('')
        return '+'.join(parts)

    def table_row(row):
        parts = ['']
        for width, cell in zip(widths, row):
            parts.append(' %s ' % cell.ljust(width))
        parts.append('')
        return '|'.join(parts)

    print("Total: %s vulnerabilities." % len(table), file=fp)
    print(file=fp)
    print(table_line('-'), file=fp)
    print(table_row(headers), file=fp)
    print(table_line('='), file=fp)
    for row in table:
        print(table_row(row[:-1] + [row[-1][0]]), file=fp)
        for fix in row[-1][1:]:
            print(table_row([''] * (len(headers) - 1) + [fix]), file=fp)
        print(table_line('-'), file=fp)
    print(file=fp)
    print(file=fp)



class RenderDoc:
    def __init__(self, python_path, date_filename, tags_filename, bugs_filename, cve_path, vuln_path):
        self.commit_dates = CommitDates(python_path, date_filename)
        self.commit_tags = CommitTags(python_path, tags_filename)
        self.python_releases = PythonReleases()
        self.bugs = PythonBugs(bugs_filename)
        self.cves = CVERegistry(cve_path)
        self.vuln_path = vuln_path

    def load_vulnerabilities(self, filename):
        vulnerabilities = []
        for data in load_yaml(filename):
            vuln = Vulnerability(self, data)
            vulnerabilities.append(vuln)

        vulnerabilities.sort(key=Vulnerability.sort_key)
        return vulnerabilities

    def main(self, yaml_filename, output_filename):
        vulnerabilities = self.load_vulnerabilities(yaml_filename)

        with open(output_filename, 'w', encoding='utf-8') as fp:
            render_table(fp, vulnerabilities)

            try_mkdir(self.vuln_path)
            filenames = []
            for vuln in vulnerabilities:
                filename = os.path.join(self.vuln_path, vuln.slug + '.rst')
                render_vuln(filename, vuln)
                filenames.append(filename)

            render_filenames(fp, filenames)

        print("{} generated".format(output_filename))


def main():
    yaml_filename = "vulnerabilities.yaml"
    rst_filename = 'vulnerabilities.rst'
    date_filename = 'commit_dates.txt'
    tags_filename = 'commit_tags.txt'
    bugs_filename = 'bugs.txt'
    cve_path = 'cve'
    vuln_path = 'vuln'
    python_path = '/home/haypo/prog/python/master'

    app = RenderDoc(python_path, date_filename, tags_filename, bugs_filename, cve_path, vuln_path)
    app.main(yaml_filename, rst_filename)


if __name__ == "__main__":
    main()
