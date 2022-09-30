import argparse
import os
import sys
import pickle
from qiling import *
from qiling.os.uefi.const import *
from qiling.const import QL_VERBOSE

def run(args):
    print(args)
    if args.nvram_file == None:
        env = []
    else:
        with open(args.nvram_file, "rb") as nv:
            env = pickle.load(nv)

    if args.extra_modules == None:
        args.extra_modules = []

    ql = Qiling(args.extra_modules + [args.target], ".", env = env, verbose=QL_VERBOSE.DEFAULT)
    ql.run()


def main(args):
    run(args)
    os._exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="프로그램 실행 모드 선택", choices=["run", "fuzz"])
    parser.add_argument("target")
    parser.add_argument("-x", "--extra-modules", help="Extra modules to load", nargs='+')
    parser.add_argument("-v", "--nvram-file", help="Pickled dictionary containing the NVRAM environment variables")
    parser.add_argument("-o", "--verbose", help="Trace execution for debugging purposes", choices=["QL_VERBOSE.DEFAULT", "QL_VERBOSE.DEBUG", "QL_VERBOSE.DISASM", "QL_VERBOSE.OFF", "QL_VERBOSE.DUMP"])

    subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")
    nvram_subparsers = subparsers.add_parser("nvram")
    nvram_subparsers.add_argument("varname", help="Mutation할 NVRAM 변수명")
    nvram_subparsers.add_argument("input", help="Mutation된 input file == @@")
    main(parser.parse_args())