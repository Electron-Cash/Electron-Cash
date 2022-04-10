#!/usr/bin/env python

import sys

import pefile

if len(sys.argv) < 2:
    sys.stderr.write(f'Usage: fix-pe-timestamp.py <pe filename>')
    sys.exit(1)

pe_filename = sys.argv[1]

pe = pefile.PE(pe_filename)

pe.FILE_HEADER.TimeDateStamp = 0xffffffff

for de in pe.DIRECTORY_ENTRY_DEBUG:
    de.struct.TimeDateStamp = 0xffffffff

pe.write(filename=pe_filename)

sys.exit(0)
