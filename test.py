#!/usr/bin/python3

from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_INS_RDMSR
import unicornafl
unicornafl.monkeypatch()
import argparse
from qiling import Qiling
import pefile
from unicorn import *
import fault

parser = argparse.ArgumentParser()

# Positional arguments
parser.add_argument("target", help="Path to the target binary to fuzz")


subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")

# NVRAM sub-command
nvram_subparser = subparsers.add_parser("nvram")
nvram_subparser.add_argument("varname")
nvram_subparser.add_argument("infile")

args = parser.parse_args()

ql = Qiling([args.target],".",output="trace")

target = ql.loader.images[-1].path
image_base = ql.loader.images[-1].base
pe = pefile.PE(target, fast_load=True)
entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
print("===============================================")
print("Loaded image's BaseAddr: "+str(hex(image_base)))
print("AddressOfEntryPoint    : "+str(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)))
print("EntryPoint             : "+str(hex(entry_point)))
print("===============================================")

def start_afl(_ql: Qiling, user_data):
    """
    Callback from inside
    """

    (varname, infile) = user_data

    def place_input_callback_nvram(uc, _input, _, data):
        """
        Injects the mutated variable to the emulated NVRAM environment.
        """
        _ql.env[varname] = _input

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        if hasattr(_ql.os.heap, "validate"):
            if not _ql.os.heap.validate():
                # Canary was corrupted.
                verbose_abort(_ql)
                return True

        crash = (_ql.internal_exception is not None) or (err.errno != UC_ERR_OK)
        return crash

    # Choose the function to inject the mutated input to the emulation environment,
    # based on the fuzzing mode.
    place_input_callback = place_input_callback_nvram

    # We start our AFL forkserver or run once if AFL is not available.
    # This will only return after the fuzzing stopped.
    try:
        if not _ql.uc.afl_fuzz(input_file=infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=False,
                               validate_crash_callback=validate_crash):
            print("Dry run completed successfully without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise


ql.hook_address(callback=start_afl, address=entry_point, user_data=(args.varname, args.infile))
try:
	ql.run(end=None, timeout=0)
except fault.ExitEmulation:
	pass