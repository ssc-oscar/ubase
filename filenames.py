#!/usr/bin/env python

import argparse
import logging

from oscar import *


DEFAULT_EXTENSIONS = ('py',)


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
    parser.add_argument('extensions', default=DEFAULT_EXTENSIONS, nargs="*",
                        help='File extensions to use')
    parser.add_argument('-o', '--output', default="-",
                        type=argparse.FileType('w'),
                        help='Output filename, "-" or skip for stdout')
    args = parser.parse_args()
    extensions = args.extensions
    counter = 0

    for file_obj in File.all():  # 2.6B file paths total; 32M *.py paths

        logging.warning("Processing file #%d: %s", counter, fname)
        counter += 1

        fname = str(file_obj)
        # TODO: perhaps, usuer fnmatch?
        if file_extension(fname) not in extensions:
            continue

        args.output.write(fname)
        args.output.write("\n")
