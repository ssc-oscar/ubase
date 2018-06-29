#!/usr/bin/env python

import argparse
from fnmatch import fnmatch
import logging

from oscar import *


DEFAULT_PATTERN = '*.py'


def file_extension(fname):
    """ Get filename extension
    Basically, the part of the filename after the last dot (if any)

    >>> file_extension('/etc/ssh.d/config.d')
    'd'
    >>> file_extension('/etc/ssh.d/config')
    ''
    >>> file_extension('/etc/sshd/.config')
    'config'
    """
    chunks = str(fname).rstrip().rsplit("/", 1)[-1].rsplit(".", 1)
    if len(chunks) < 2:
        return ''
    return chunks[-1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get all filenames with the specified extension(s)")
    parser.add_argument('pattern', default=DEFAULT_PATTERN, nargs="?",
                        help='File extensions to use')
    parser.add_argument('-o', '--output', default="-",
                        type=argparse.FileType('w'),
                        help='Output filename, "-" or skip for stdout')
    args = parser.parse_args()
    counter = 0

    for file_obj in File.all():  # 2.6B file paths total; 32M *.py paths
        path = str(file_obj)

        logging.warning("Processing file #%d: %s", counter, path)
        counter += 1

        if fnmatch(path, args.pattern):
            continue

        args.output.write(path)
        args.output.write("\n")
