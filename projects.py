#!/usr/bin/env python

import pandas as pd

import argparse
import logging
import os

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
    parser.add_argument('-S', '--snapshots-dir', type=str, nargs="?",
                        help='Directory path to for intermediate snapshots')
    parser.add_argument('-s', '--snapshots-interval', default=100000, type=int,
                        help='Snapshots interval, every processed N files')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Log progress to stderr")
    args = parser.parse_args()

    if args.snapshots_dir and not os.path.isdir(args.snapshots_dir):
        parser.exit(1, "Snapshot dir does not exist")

    logging.basicConfig(format='%(asctime)s %(message)s',
                        level=logging.INFO if args.verbose else logging.WARNING)

    projects = set()
    projects_list = []  # an ordered version of projects for snapshots
    counter = 0

    def snapshot():
        if not args.snapshots_dir:
            return
        s = pd.Series(projects_list)
        path = os.path.join(
            args.snapshots_dir,
            "projects_snapshot_%d.csv" % counter)
        s.to_csv(path, index=False)

    # 2.6B file paths total; 32M *.py paths
    for counter, fname in enumerate(args.input):
        # fun fact: csv.writer uses \r\n endings even on Linux
        fname = fname.rstrip("\r\n")
        file_obj = File(fname)

        logging.info("Processing file #%d: %s", counter, fname)

        for commit in file_obj.commits:
            for project in commit.project_names:
                if project not in projects:
                    projects_list.append(project)
                    args.output.write(project)
                    args.output.write("\n")
                    args.output.flush()
                    projects.add(project)

                    if counter and not counter % args.snapshots_interval:
                        snapshot()

    snapshot()
