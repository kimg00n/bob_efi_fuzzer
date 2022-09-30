import argparse
import os
import sys
import pickle
from qiling import *
from qiling.os.uefi.const import *

def run(args):
    with open(args.nvram_file, "rb") as nv:
        env = pickle.load(nv)

    ql = Qiling([args.target], ".", env = env)
    ql.run()


def main(args):
    run(args)
    os._exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="프로그램 실행 모드 선택", choices=["run", "fuzz"])
    parser.add_argument("target")
    parser.add_argument("-v", "--nvram-file", help="Pickled dictionary containing the NVRAM environment variables")
    parser.add_argument("-o", "--output", help="Trace execution for debugging purposes", choices=["default", "disabled", "debug", "disasm", "dump"])

    subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")
    nvram_subparsers = subparsers.add_parser("nvram")
    nvram_subparsers.add_argument("varname", help="Mutation할 NVRAM 변수명")
    nvram_subparsers.add_argument("input", help="Mutation된 input file == @@")
    main(parser.parse_args())