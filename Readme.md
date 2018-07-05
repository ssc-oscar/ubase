
Mine usage of Python libraries using OSCAR dataset

Usage:

    ./filenames.py -o filenames.csv
    ./projects.py -i filenames.csv -o projects.csv
    ./ubase.py -i projects.csv

Recommended usage:

    mkdir snapshots

    ./filenames.py | tee filenames.csv | \
        ./projects.py -S snapshots | tee projects.csv | \
        ./ubase.py -S snapshots -v -o ubase.csv