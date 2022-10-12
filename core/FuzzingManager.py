from core.EmulationManager import EmulationManager
from unicorn import *
import unicornafl
import pefile
from qiling import Qiling
import os
from qiling.extensions import afl

def verbose_abort(ql):
    ql.os.emu_error()
    os.abort()

def start_afl(_ql: Qiling, user_data):
    (varname, infile) = user_data

    def place_input_callback(ql: Qiling, input: bytes, _):
        ql.env[varname] = input
    
    def validate_crash(err):
        if hasattr(_ql.os.heap, "validate"):
            if not _ql.os.heap.validate():
                verbose_abort(_ql)
                return True
        
        crash = (_ql.internal_exception is not None) or (err.errno != UC_ERR_OK)
        return crash
    
    try:
        if not afl.ql_afl_fuzz(_ql,
                                input_file=infile,
                                place_input_callback=place_input_callback,
                                exits=[_ql.os.exit_point],
                                always_validate=True,
                                validate_crash_callback=validate_crash):

                                print("Dry run completed successfully without AFL attached.")
                                os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise

class FuzzingManager(EmulationManager):
    
    DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None):
        super().__init__(target_module, extra_modules)

        self.sanitizers = FuzzingManager.DEFAULT_SANITIZERS
        self.fault_handler = 'abort'
    
    def fuzz(self, end=None, timeout=0, **kwargs):
        target = self.ql.loader.images[-1].path
        pe = pefile.PE(target, fast_load=True)
        image_base = self.ql.loader.images[-1].base
        entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # We want AFL's forkserver to spawn new copies starting from the main module's entrypoint.
        self.ql.hook_address(callback=start_afl, address=entry_point, user_data=(kwargs['varname'], kwargs['infile']))

        super().run(end, timeout)