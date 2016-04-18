#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

# search.py - simple script that lets you quickie search for regexp

import immlib

# TODO: -a <ASM> -m <modname>, search all on no -m
# TODO: migrate/replace searchcode.py

DESC = "Search for given assembly code"

def usage(imm):
    imm.Log("!search <ASM>")

def main(args):
    if not args:
        return "Usage: !search <ASM>"
    imm = immlib.Debugger()
    code = " ".join(args)
    ret = imm.searchCommands(code.upper())
    for a in ret:
        imm.Log("Found %s at 0x%X (%s)"% (a[1], a[0], a[2]), focus=1)
    return "Search completed!"

