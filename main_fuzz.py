#!/usr/bin/python3

from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_INS_RDMSR
import unicornafl
unicornafl.monkeypatch()
import argparse
from qiling import Qiling
import pefile
from unicorn import *
import fault
import set_ql as set_ql

parser = argparse.ArgumentParser()

# Positional arguments
parser.add_argument("command", choices=['fuzz', 'ida', 'gdb'])
parser.add_argument("target", help="Path to the target binary to fuzz")


parser.add_argument("-n", "--nvram-file")
parser.add_argument("-t", "--timeout", help="Emulation timeout in ms", type=int, default=60*100000)


subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")

# NVRAM sub-command
nvram_subparser = subparsers.add_parser("nvram")
nvram_subparser.add_argument("varname")
nvram_subparser.add_argument("infile")

args = parser.parse_args()


set_ql.main(args)

