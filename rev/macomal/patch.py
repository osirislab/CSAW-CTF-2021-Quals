#!/usr/bin/env python3
import sys
import lief

if len(sys.argv) != 2:
    print("Mach-O input needed")
    sys.exit(1)

file = lief.parse(sys.argv[1])
file.add_library("injected.dylib")
file.write(sys.argv[1])
print("Done")
