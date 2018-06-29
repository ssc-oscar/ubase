#!/usr/bin/env python

import pandas as pd

import argparse
from collections import defaultdict
from fnmatch import fnmatch
import logging
import re

from filenames import DEFAULT_PATTERN
from oscar import *


# libraries.io only looks for `from ...`:
# https://github.com/librariesio/pydeps/blob/master/pydeps.rb
# {pn} = package name pattern
# there are no commas in from X import ..., but for simplicity it's ok
IMPORT_PATTERN = re.compile(
    "^\s*(?:from|import)\s+({pn}(?:\s*,\s*{pn})*)".format(pn="[a-zA-Z0-9\._]*"),
    re.M)


# Combined from
# https://docs.python.org/2/library/index.html
# https://docs.python.org/3/library/index.html
BUILTINS = {
    '', 'AL', 'BaseHTTPServer', 'Bastion', 'CGIHTTPServer', 'ColorPicker',
    'ConfigParser', 'Cookie', 'DEVICE', 'DocXMLRPCServer', 'EasyDialogs', 'FL',
    'FrameWork', 'GL', 'HTMLParser', 'MacOS', 'MimeWriter', 'MiniAEFrame',
    'Queue', 'SUNAUDIODEV', 'ScrolledText', 'SimpleHTTPServer',
    'SimpleXMLRPCServer', 'SocketServer', 'StringIO', 'Tix', 'Tkinter',
    'UserDict', 'UserList', 'UserString', '__builtin__', '__future__',
    '__main__', '_dummy_thread', '_thread', '_winreg', 'abc', 'aepack',
    'aetools', 'aetypes', 'aifc', 'al', 'and', 'anydbm', 'argparse', 'array',
    'ast', 'asynchat', 'asyncio', 'asyncore', 'atexit', 'audioop', 'autoGIL',
    'base64', 'bdb', 'binascii', 'binhex', 'bisect', 'bsddb', 'buffer',
    'builtins', 'bytearray', 'bytes', 'bz2', 'cPickle', 'cStringIO',
    'calendar', 'cd', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd', 'code',
    'codecs', 'codeop', 'collections', 'colorsys', 'commands', 'compileall',
    'complex', 'concurrent', 'configparser', 'contextlib', 'cookielib', 'copy',
    'copy_reg', 'copyreg', 'crypt', 'csv', 'ctypes', 'curses', 'datetime',
    'dbhash', 'dbm', 'decimal', 'dict', 'difflib', 'dircache', 'dis',
    'distutils', 'dl', 'doctest', 'dumbdbm', 'dummy_thread', 'dummy_threading',
    'email', 'ensurepip', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp',
    'fileinput', 'findertools', 'fl', 'float', 'flp', 'fm', 'fnmatch',
    'formatter', 'fpectl', 'fpformat', 'fractions', 'frozenset', 'ftplib',
    'functools', 'future_builtins', 'gc', 'gdbm', 'gensuitemodule', 'getopt',
    'getpass', 'gettext', 'gl', 'glob', 'grp', 'gzip', 'hashlib', 'heapq',
    'hmac', 'hotshot', 'html', 'htmlentitydefs', 'htmllib', 'http', 'httplib',
    'ic', 'imageop', 'imaplib', 'imgfile', 'imghdr', 'imp', 'import',
    'importlib', 'imputil', 'inspect', 'int', 'io', 'ioctl', 'ipaddress',
    'itertools', 'jpeg', 'json', 'keyword', 'linecache', 'list', 'locale',
    'logging', 'long', 'lzma', 'macostools', 'macpath', 'mailbox', 'mailcap',
    'marshal', 'math', 'md5', 'memoryview', 'mhlib', 'mimetools', 'mimetypes',
    'mimify', 'mmap', 'modulefinder', 'msilib', 'msvcrt', 'multifile',
    'multiprocessing', 'mutex', 'netrc', 'new', 'nis', 'nntplib', 'not',
    'numbers', 'operator', 'optparse', 'or', 'os', 'ossaudiodev', 'parser',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pip', 'pipes', 'pkgutil',
    'platform', 'plistlib', 'popen2', 'poplib', 'posix', 'posixfile', 'pprint',
    'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri', 'random',
    'range', 're', 'readline', 'repr', 'reprlib', 'resource', 'rexec', 'rfc822',
    'rlcompleter', 'robotparser', 'runpy', 'sched', 'secrets', 'select',
    'selectors', 'set', 'sets', 'sgmllib', 'sha', 'shelve', 'shlex', 'shutil',
    'signal', 'site', 'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver',
    'spwd', 'sqlite3', 'ssl', 'stat', 'statistics', 'statvfs', 'str', 'string',
    'stringprep', 'struct', 'subprocess', 'sunau', 'sunaudiodev', 'symbol',
    'symtable', 'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile',
    'telnetlib', 'tempfile', 'termios', 'test', 'textwrap', 'thread',
    'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace',
    'traceback', 'tracemalloc', 'ttk', 'tty', 'tuple', 'turtle', 'types',
    'typing', 'unicode', 'unicodedata', 'unittest', 'urllib', 'urllib2',
    'urlparse', 'user', 'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref',
    'webbrowser', 'whichdb', 'winreg', 'winsound', 'with', 'wsgiref', 'xdrlib',
    'xmlrpc', 'xmlrpclib', 'xrange', 'zipapp', 'zipfile', 'zipimport', 'zlib'
}


def top_namespace(namespace):
    """ Get the top level namespace

    For relative imports, an empty string is returned.

    >>> top_namespace('matplotlib.pyplot')
    'matplotlib'
    >>> top_namespace('pandas')
    'pandas'
    >>> top_namespace('.utils')
    ''
    """
    return namespace.split('.', 1)[0]


def blob_imports(blob_sha, max_size=4096):
    """ Mine import statements in a Python file.
    Notes:
        - it only returns top-level dependencies
          (e.g. `from x imoprt y` will consider `x` only, not `x.y`)
        - it also returns builtins
          (it will include csv if there is an `import csv` statement)
        - it doesn't handle `importlib` magic
        - it doesn't check if the code is commented out or unreachable

    How it works:
        look for lines `import X [as Y]` and `from X import Y`
        return list of X-es

    Package name can have:
        lower and capital case letters, digits, underscores
        Note: it cannot start with a digit (underscore is fine)
    Package name cannot contain:
        hyphen, dot, or start with a digit

    Special case: multiple imports:
        `import csv, re`

    :param blob_sha: sha of the blob to use
    :param max_size: max number of data bytes to consider
    :return: generator of dependencies as strings

    # https://github.com/django/django/tree/42eb0c09
    >>> files = Commit('42eb0c09bcf062b9336d1f1a728813e4a599ad47').tree.files
    >>> blob_imports(files['scripts/manage_translations.py'])
    ['os', 'argparse', 'subprocess', 'django.core.management']

    # https://github.com/tornadoweb/tornado/tree/5e7e0577
    >>> files = Commit('5e7e05773913221bc168f4dd3a24bcee22d63bef').tree.files
    >>> blob_imports(files['setup.py'])  # doctest: +NORMALIZE_WHITESPACE
    ['os', 'platform', 'sys', 'warnings', 'setuptools', 'setuptools',
     'distutils.core', 'distutils.core', 'distutils.command.build_ext']

    """
    # 2m without doing anything
    # 3m with data read only
    # 4m with multiline re
    # 20m per 166 projects for the full cycle split+match by line

    return IMPORT_PATTERN.findall(Blob(blob_sha).data[:max_size])


def importable_paths(path):
    """ Get a list of modules that could be imported locally

    Python 3 doesn't require __init__.py files to consider folder a module,
    so any folders with Python files are also included.

    >>> importable_paths('my_module/utils.py')
    ['my_module', 'utils']
    """
    chunks = [chunk
              for chunk in path.split("/")
              if chunk and (chunk[0].isalpha() or chunk[0] == "_")]
    if chunks:
        chunks[-1] = chunks[-1].rsplit('.', 1)[0]
    return chunks


def commit_imports(commit, imports_cache=None, pattern=DEFAULT_PATTERN):
    # type: (Commit, dict, str) -> dict
    """ Get commit imports

    How it works:
        - collect all blob imports
        - take only top namespaces (i.e. django out of django.foo.bar)
        - removes local imports (i.e. my_module if my_module.py is present)
        - removes builtins (like csv, multiprocessing etc)

    Args:
        commit (oscar.Commit): a commit to analyze
        imports_cache (dict): a dictionary of blob_sha: set(top namespaces)
        pattern (str): filename pattern to consider, *.py by default

    Returns:
        dict: blob_sha: set of top namespaces
    """
    cache = imports_cache or {}
    if commit is None:
        return {}
    # paths: file path: blob sha
    paths = {path: blob_sha for path, blob_sha in commit.tree.files.items()
             if fnmatch(path, pattern) and 'test' not in path}

    filenames = set().union(*(importable_paths(path) for path in paths))

    # blob imports: blob sha: set(top namespaces)
    imports = {blob_sha: cache.get(blob_sha,
        {top_namespace(ns) for ns in blob_imports(blob_sha)}
                    - filenames - BUILTINS)
          for blob_sha in paths.values()}

    return imports


def commits_fp_monthly(commits):
    """ Filter out Project.commits_fp to only leave latest commit in a month

    This method is concieved as performance optimization - since we aggregate
    usage by month, it makes sense to only view last commit in a month.

    Commits with invalid dates (dead CMOS battery, invalid data etc) have None
    as authored date and will be ignored.
    """
    month = None
    for commit in commits:
        if (commit.authored_at and month != commit.authored_at.strftime("%Y-%m")
             ) or not commit.parent_shas:
            month = commit.authored_at.strftime("%Y-%m")
            yield commit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Count Python namespace usage given a list of projects")
    parser.add_argument('pattern', default=DEFAULT_PATTERN, nargs="?",
                        help='File extensions to use')
    parser.add_argument('-i', '--input', default="-",
                        type=argparse.FileType('r'),
                        help='Input filename, "-" or skip for stdin')
    parser.add_argument('-o', '--output', default="-",
                        type=argparse.FileType('w'),
                        help='Output filename, "-" or skip for stdout')
    args = parser.parse_args()
    projects = args.input

    # projects = ['user2589_minicms'] #, 'YeonjuGo_cmssw']

    logging.basicConfig(format='%(asctime)s %(message)s')

    # 57 bytes of RAM to store 20-char bin_sha
    # bool: 24 bytes
    # dict overhead: 48 bytes per key-value pair
    # Total: 57 + 24 + 48 = 129 bytes per commit
    # worst case: 1B commits = 129Gb RAM
    # 700+ GB available, so it should work
    processed_commits = {}  # bin_sha: bool(terminal)
    missing_parents = 0
    stats = defaultdict(
        lambda: defaultdict(int))  # [namespace][month] = increment
    counter = 0

    for project_name in projects:  # ~800M projects in total, ?? use Python
        project_name = project_name.rstrip("\r\n")
        if project_name == 'EMPTY':  # special value
            continue
        project = Project(project_name)

        commits = tuple(project.commits_fp)
        full_length = len(commits)
        commits = tuple(commits_fp_monthly(commits))
        reduced_length = len(commits)

        logging.warning("#%d: %s (%d/%d commits)", counter, project_name,
                        full_length, reduced_length)
        counter += 1

        imports = None
        cum_imports = set()
        for commit in commits:
            if commit.bin_sha in processed_commits:
                if imports is not None:
                    processed_commits[commit.bin_sha] = False
                break
            logging.debug("Processing %s", commit.sha)
            try:
                parent = commit.parents.next()
            except StopIteration:
                parent = None
            except ObjectNotFound:
                # one of rare cases we don't have parent commit data
                # Assumption: nothing changed
                missing_parents += 1
                continue
            # mark commit as processed
            processed_commits[commit.bin_sha] = imports is None

            if imports is None:  # starting from project head commit
                try:  # handle missing Tree objects
                    # in this case, it is more appropriate to ignore this commit
                    # than to consider it empty, because it will be recorded
                    # as removal of all dependencies
                    imports = commit_imports(commit, {}, args.pattern)
                except ObjectNotFound:
                    continue
                cum_imports = set().union(*imports.values())

            try:  # similar to the imports above
                parent_imports = commit_imports(parent, imports, args.pattern)
            except ObjectNotFound:
                continue

            date = commit.authored_at.strftime("%Y-%m")

            cum_parent_imports = set().union(*parent_imports.values())

            deleted = cum_parent_imports - cum_imports
            added = cum_imports - cum_parent_imports

            for dep in deleted:
                stats[dep][date] -= 1
            for dep in added:
                stats[dep][date] += 1

            commit = parent
            imports = parent_imports
            cum_imports = cum_parent_imports

    df = pd.DataFrame(stats).T
    df.fillna(0).astype(int).to_csv(args.output)
    logging.warning("Missing parents: %d", missing_parents)
