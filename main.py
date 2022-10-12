import argparse
import os
import functools
from unicorn import *
from core.EmulationManager import EmulationManager
from core.FuzzingManager import FuzzingManager
import sanitizers

auto_int = functools.partial(int, base=0)

def create_emulator(cls, args):
    emu = cls(args.target, args.extra_modules)
    
    # Load NVRAM environment from the provided Pickle.
    if args.nvram_file:
        emu.load_nvram(args.nvram_file)

    # Set the fault handling policy.
    if args.fault_handler:
        emu.fault_handler = args.fault_handler

    # Initialize SMRAM and some SMM-related protocols.
    #emu.enable_smm()

    # Enable sanitizers.
    if args.sanitize:
        emu.sanitizers = args.sanitize

    return emu

def run(args):
    emu = create_emulator(EmulationManager, args)
    emu.run(args.end, args.timeout)

def fuzz(args):
    emu = create_emulator(FuzzingManager, args)
    emu.fuzz(args.end, args.timeout, varname=args.varname, infile=args.infile)

def main(args):
    if args.command == 'run':
        run(args)
    elif args.command == 'fuzz':
        fuzz(args)
    os._exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="프로그램 실행 모드 선택", choices=["run", "fuzz"])
    parser.add_argument("target")
    parser.add_argument("-x", "--extra-modules", help="Extra modules to load", nargs='+')
    parser.add_argument("-v", "--nvram-file", help="Pickled dictionary containing the NVRAM environment variables")
    parser.add_argument("-o", "--verbose", help="Trace execution for debugging purposes", choices=["QL_VERBOSE.DEFAULT", "QL_VERBOSE.DEBUG", "QL_VERBOSE.DISASM", "QL_VERBOSE.OFF", "QL_VERBOSE.DUMP"], default="QL_VERBOSE.DEFAULT")
    parser.add_argument("-s", "--sanitize", help="Enable memory sanitizer", choices=sanitizers.get_available_sanitizers().keys(), nargs='+')
    parser.add_argument("-g", "--gdb", help="Enable gdb server at run mode", default="n")
    parser.add_argument("-e", "--end", help="End address for emulation", type=auto_int)
    parser.add_argument("-t", "--timeout", help="Emulation timeout in ms", type=int, default=60*100000)
    parser.add_argument("-f", "--fault-handler", help="What to do when encountering a fault?", choices=['crash', 'stop', 'ignore', 'break'])

    subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")
    nvram_subparsers = subparsers.add_parser("nvram")
    nvram_subparsers.add_argument("varname", help="Mutation할 NVRAM 변수명")
    nvram_subparsers.add_argument("infile", help="Mutation된 input file == @@")
    main(parser.parse_args())