import unicornafl
unicornafl.monkeypatch()
import argparse
from qiling import Qiling
import pefile
from unicorn import *
import update_ql as update_ql

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

    place_input_callback = place_input_callback_nvram

    try:
        if not _ql.uc.afl_fuzz(input_file=infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=False,
                               validate_crash_callback=validate_crash):
            print("Dry run completed successfully without AFL attached.")
            os._exit(0)
    except unicornafl.UcAflError as ex:
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise


def main(args):
    ql = Qiling([args.target],".",output="trace")

    update_ql.ckeck_option(ql,args)

    if "gdb" in args.command:
        ql.debugger = "gdb:127.0.0.1:9999"
        ql.log.info("")
        ql.log.info("To debug attach localhost:9999")
    #elif "ida" in args.command:
    #    ql.debugger = "idapro:127.0.0.1:9999"

    target = ql.loader.images[-1].path
    image_base = ql.loader.images[-1].base
    pe = pefile.PE(target, fast_load=True)
    entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

    ql.log.info("===============================================")
    ql.log.info("Loaded image's BaseAddr: "+str(hex(image_base)))
    ql.log.info("AddressOfEntryPoint    : "+str(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)))
    ql.log.info("EntryPoint             : "+str(hex(entry_point)))
    ql.log.info("===============================================")

    ql.hook_address(callback=start_afl, address=entry_point, user_data=(args.varname, args.infile))

    try:
        ql.run(end=None, timeout=args.timeout)
    except fault.ExitEmulation:
        pass