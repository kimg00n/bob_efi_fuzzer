from . import protocols
from qiling.os.uefi.utils import write_int64
from qiling.os.uefi.ProcessorBind import STRUCT, UINTN
from qiling.os.memory import QlMemoryHeap
#from .swsmi import trigger_swsmi

class SmmSegment:
    def __init__(self, ql, name):
        self.base = int(ql.os.profile.get(name, "base"), 0)
        self.size = int(ql.os.profile.get(name, "size"), 0)
        if ql.os.profile.has_option(name, "heap_size"):
            self.heap_size = int(ql.os.profile.get(name, "heap_size"), 0)
        else:
            self.heap_size = 0

        ql.mem.map(self.base, self.size - self.heap_size, info=f"[SMM {name.upper()}]")

        if self.heap_size > 0:
            heap_base = self.base + self.size - self.heap_size
            heap_end = self.base + self.size
            self.heap = QlMemoryHeap(ql, heap_base, heap_end)
        else:
            self.heap = None
    
    def heap_alloc(self, size):
        if self.heap:
            return self.heap.alloc(size)
        return 0
    
    def overlaps(self, address):
        return (address >= self.base) and (address < self.base + self.size)
    
class SmmState(object):

    PAGE_SIZE = 0x1000

    def __init__(self, ql):
        self.swsmi_handlers = {}
        self.smbase = int(ql.os.profile.get("smm", "smbase"), 0)
        self.swsmi_args = {}

        