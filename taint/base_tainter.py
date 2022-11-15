import triton
from abc import ABC, abstractmethod
from sanitizers.base_sanitizer import base_sanitizer
import taint.tracker
class base_tainter(base_sanitizer):

    def __init__(self, ql):
        super().__init__(ql)

        # Build and initialize a TritonContext.
        self.triton_ctx = triton.TritonContext()
        self.triton_ctx.setArchitecture(triton.ARCH.X86_64)
        self.triton_ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.triton_ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

    def enable(self):
        if not hasattr(self.ql, 'tainters'):
            self.ql.tainters = {}
            taint.tracker.enable(self.ql)

        self.ql.tainters[self.NAME] = self

    def sync(self, ql):
        from unicorn.x86_const import UC_X86_REG_EFLAGS

        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rax, ql.arch.regs.rax)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rbx, ql.arch.regs.rbx)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rcx, ql.arch.regs.rcx)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rdx, ql.arch.regs.rdx)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rdi, ql.arch.regs.rdi)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rsi, ql.arch.regs.rsi)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rbp, ql.arch.regs.rbp)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rsp, ql.arch.regs.rsp)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rip, ql.arch.regs.rip)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r8, ql.arch.regs.r8)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r9, ql.arch.regs.r9)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r10, ql.arch.regs.r10)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r11, ql.arch.regs.r11)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r12, ql.arch.regs.r12)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r13, ql.arch.regs.r13)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r14, ql.arch.regs.r14)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r15, ql.arch.regs.r15)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.eflags, ql.arch.regs.read(UC_X86_REG_EFLAGS))
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.fs, ql.arch.regs.fs)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.gs, ql.arch.regs.gs)

    @abstractmethod
    def instruction_hook(self, ql, instruction):
        raise NotImplementedError()

    #
    # Taint utilities
    #

    def set_taint_range(self, begin, end, taint):
        # Apply taint for the entire memory range.
        taint_func = self.triton_ctx.taintMemory if taint else self.triton_ctx.untaintMemory
        for addr in range(begin, end + 1):
            taint_func(addr)

    def get_taint_range(self, begin, end):
        return [self.triton_ctx.isMemoryTainted(addr) for addr in range(begin, end + 1)]

    def copy_taint(self, source, destination, length):
        for i in range(length):
            if self.triton_ctx.isMemoryTainted(source + i):
                self.triton_ctx.taintMemory(destination + i)
            else:
                self.triton_ctx.untaintMemory(destination + i)

    def is_range_tainted(self, begin, end):
        return any(self.get_taint_range(begin, end))
