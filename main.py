import argparse
import os
import sys
import pickle
from qiling import *
from qiling.os.uefi.const import *
from qiling.const import QL_VERBOSE
from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap

def my_abort(msg):
    print(f"\n*** {msg} ***\n")
    os.abort()

def enable_sanitized_heap(ql, fault_rate=0):
    heap = QlSanitizedMemoryHeap(ql, ql.os.heap, fault_rate=fault_rate)

    heap.oob_handler      = lambda *args: my_abort(f'Out-of-bounds read detected')
    heap.bo_handler       = lambda *args: my_abort(f'Buffer overflow/underflow detected')
    heap.bad_free_handler = lambda *args: my_abort(f'Double free or bad free detected')
    heap.uaf_handler      = lambda *args: my_abort(f'Use-after-free detected')

    # make sure future allocated buffers are not too close to UEFI data
    heap.alloc(0x1000)

    ql.os.heap = heap
    ql.loader.dxe_context.heap = heap

def run(args):
    print(args)
    if args.nvram_file == None:
        env = []
    else:
        with open(args.nvram_file, "rb") as nv:
            env = pickle.load(nv)

    if args.extra_modules == None:
        args.extra_modules = []

    ql = Qiling(args.extra_modules + [args.target], ".", env = env, verbose=QL_VERBOSE.DEBUG)
    if args.sanitize == "y":
        enable_sanitized_heap(ql)
    ql.run()
    if not ql.os.heap.validate():
        my_abort("Canary corruption detected")

def fuzz(args):
    print(args)
    if args.nvram_file == None:
        env = []
    else:
        with open(args.nvram_file, "rb") as nv:
            env = pickle.load(nv)

    if args.extra_modules == None:
        args.extra_modules = []

    ql = Qiling(args.extra_modules + [args.target], ".", env = env, verbose=QL_VERBOSE.DEBUG)
    enable_sanitized_heap(ql)
    ql.run()
    if not ql.os.heap.validate():
        my_abort("Canary corruption detected")


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
    parser.add_argument("-s", "--sanitize", help="Enable heap sanitizer", choices=["y", "n"], defualt="y")

    subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")
    nvram_subparsers = subparsers.add_parser("nvram")
    nvram_subparsers.add_argument("varname", help="Mutation할 NVRAM 변수명")
    nvram_subparsers.add_argument("input", help="Mutation된 input file == @@")
    main(parser.parse_args())