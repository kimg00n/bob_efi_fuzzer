import pickle
from qiling import Qiling
from qiling.const import QL_VERBOSE
from . import fault
import sanitizers
from . import callbacks

class EmulationManager:

    DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None):

        if extra_modules is None:
            extra_modules = []
        
        self.ql = Qiling(extra_modules + [target_module], '.', verbose=QL_VERBOSE.DEFAULT)

        self.sanitizers = EmulationManager.DEFAULT_SANITIZERS
        self.fault_handler = 'exit'

    def load_nvram(self, nvram_file):
        with open(nvram_file, 'rb') as nvram:
            self.ql.env.update(pickle.load(nvram))
    
    def _enable_sanitizers(self):
        self.ql.log.info(f"Enable Sanitizers {self.sanitizers}")
        for sanitizer in self.sanitizers:
            sanitizers.get(sanitizer)(self.ql).enable()
    
    @property
    def fault_handler(self):
        return self._fault_handler

    @fault_handler.setter
    def fault_handler(self, value):
        self._fault_handler = value

        if value == 'exit':
            self.ql.os.fault_handler = fault.exit
        elif value == 'abort':
            self.ql.os.fault_handler = fault.abort
        elif value == 'ignore':
            self.ql.os.fault_handler = fault.ignore
        elif value == 'break':
            self.ql.os.fault_handler = fault._break
    
    def run(self, end=None, timeout=0, **kwargs):
        
        self._enable_sanitizers()

        try:
            self.ql.run(end=end, timeout=timeout)
        except fault.ExitEmulation:
            pass