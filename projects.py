#!/usr/bin/env python

import argparse
import logging

from oscar import *


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get a list of projects that contain "
                    "any of the specified paths")
    parser.add_argument('-i', '--input', default="-",
                        type=argparse.FileType('r'),
                        help='Input filename, "-" or skip for stdin')
    parser.add_argument('-o', '--output', default="-",
                        type=argparse.FileType('w'),
                        help='Output filename, "-" or skip for stdout')
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(message)s')

    projects = set()
    counter = 0

    for fname in args.input:  # 2.6B file paths total; 32M *.py paths
        # fun fact: csv.writer uses both of \r and \n even on Linux
        fname = fname.rstrip("\r\n")
        file_obj = File(fname)

        logging.warning("Processing file #%d: %s", counter, fname)
        counter += 1

        for commit in file_obj.commits:
            for project in commit.project_names:
                if project not in projects:
                    args.output.write(project)
                    args.output.write("\n")
                    args.output.flush()
                    projects.add(project)
