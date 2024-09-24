#!/usr/bin/env python3

# Just a utility to be used for pip-audit that outputs all reqs and filter
# away btchip-python since it's broken.

FILES = ['contrib/deterministic-build/requirements-binaries.txt',
         'contrib/deterministic-build/requirements-build-wine.txt',
         'contrib/deterministic-build/requirements-hw.txt',
         'contrib/deterministic-build/requirements-pip.txt',
         'contrib/deterministic-build/requirements.txt']

FILTERED_PACKAGES = {'btchip-python'}

for f in FILES:
    with open(f) as input:
        for line in input:
            if line[0] != ' ':
                current_package = line.split('=')[0]
            if current_package in FILTERED_PACKAGES:
                continue
            print(line, end="")
