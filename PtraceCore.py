#! /usr/bin/env python

#############################################################################
##                                                                         ##
## PtraceCore --- Python Ptrace debugger                                   ##
##              see http://chdir.org/~nico/ptrace/                         ##
##              for more informations                                      ##
##                                                                         ##
## Copyright (C) 2007  Nicolas Bareil <nico@chdir.org>                     ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

import os
from ctypes import *

class PtraceCoreCtypes:
    libc = None

    def __init__(self):
        self.libc = CDLL('libc.so.6')

    def do_and_wait(self, req, pid, addr=None, data=None):
        return self.do(req, pid, addr, data, wait=True)

    def do(self, req, pid, addr=None, data=None, wait=False):
        if self.libc is None:
            raise Exception('Module not init!')
        ret=self.libc.ptrace(req, pid, addr, data)
        if wait:
            os.waitpid(pid, 0)
        return ret

class PtraceRawRegisters(Structure):
    _fields_ = [('ebx',     c_ulong),
               ('ecx',      c_ulong),
               ('edx',      c_ulong),
               ('esi',      c_ulong),
               ('edi',      c_ulong),
               ('ebp',      c_ulong),
               ('eax',      c_ulong),
               ('ds',       c_ushort),
               ('__ds',     c_ushort),
               ('es',       c_ushort),
               ('__es',     c_ushort),
               ('fs',       c_ushort),
               ('__fs',     c_ushort),
               ('gs',       c_ushort),
               ('__gs',     c_ushort),
               ('orig_eax', c_ulong),
               ('eip',      c_ulong),
               ('cs',       c_ushort),
               ('__cs',     c_ushort),
               ('eflags',   c_ulong),
               ('esp',      c_ulong),
               ('ss',       c_ushort),
               ('__ss',     c_ushort) ]

    def __str__(self):
        return '[eip=%#x eax=%#x, ebx=%#x ecx=%#x edx=%#x esi=%#x edi=%#x ebp=%#x]' % (
            self.eip, self.eax, self.ebx, self.ecx, self.edx, self.esi, self.edi, self.ebp)

# siginfo_t {
#      int      si_signo;    /* 
#      int      si_errno;    /* 
#      int      si_code;     /* 
#      pid_t    si_pid;      /* 
#      uid_t    si_uid;      /* 
#      int      si_status;   /* 
#      clock_t  si_utime;    /* 
#      clock_t  si_stime;    /* 
#      sigval_t si_value;    /* 
#      int      si_int;      /* 
#      void    *si_ptr;      /* 
#      void    *si_addr;     /* */
#      int      si_band;     /* 
#      int      si_fd;       /* 
#  }

class SignalInfo(Structure):
    _fields_ = [('signo',  c_int),       # Signal number
                ('errno',  c_int),       # An errno value
                ('code',   c_int),       # Signal code
                ('pid',    c_int),       # Sending process ID
                ('uid',    c_int),       # Real user ID of sending process
                ('status', c_int)]       # Exit value or signal
#                 ('utime',  c_int), # XXX # User time consumed
#                 ('stime',  c_int), # XXX # System time consumed
#                 ('value',  c_int),       # Signal value
#                 ('int',    c_int),       # POSIX.1b signal
#                 ('ptr',    c_void_p),    # POSIX.1b signal
#                 ('addr',   c_void_p),    # Memory location which caused fault 
#                 ('band',   c_int),       # Band event
#                 ('fd',     c_int) ]      # File descriptor

    def inSyscall(self):
        return self.code & 0x80

class PtraceCore(object):
    PTRACE_TRACEME     = 0
    PTRACE_PEEKTEXT    = 1
    PTRACE_PEEKDATA    = 2
    PTRACE_PEEKUSER    = 3
    PTRACE_POKETEXT    = 4
    PTRACE_POKEDATA    = 5
    PTRACE_POKEUSER    = 6
    PTRACE_CONT        = 7
    PTRACE_KILL        = 8
    PTRACE_SINGLESTEP  = 9
    PTRACE_GETREGS     = 12
    PTRACE_SETREGS     = 13
    PTRACE_GETFPREGS   = 14
    PTRACE_SETFPREGS   = 15
    PTRACE_ATTACH      = 16
    PTRACE_DETACH      = 17
    PTRACE_GETFPXREGS  = 18
    PTRACE_SETFPXREGS  = 19
    PTRACE_SYSCALL     = 24

    # architecture dependant
    PTRACE_SETOPTIONS  = 0x4200
    PTRACE_GETEVENTMSG = 0x4201
    PTRACE_GETSIGINFO  = 0x4202
    PTRACE_SETSIGINFO  = 0x420


    # ptrace options
    PTRACE_O_TRACESYSGOOD   = 0x01
    PTRACE_O_TRACEFORK      = 0x02
    PTRACE_O_TRACEVFORK     = 0x04
    PTRACE_O_TRACECLONE     = 0x08
    PTRACE_O_TRACEEXEC      = 0x10
    PTRACE_O_TRACEVFORKDONE = 0x20
    PTRACE_O_TRACEEXIT      = 0x40
    PTRACE_O_MASK           = 0x7f

    # 
    PTRACE_EVENT_FORK       = 1
    PTRACE_EVENT_VFORK      = 2
    PTRACE_EVENT_CLONE      = 3
    PTRACE_EVENT_EXEC       = 4
    PTRACE_EVENT_VFORK_DONE = 5
    PTRACE_EVENT_EXIT       = 6

    def __init__(self, backend=PtraceCoreCtypes):
        self.backend = backend()

    def attach(self, pid):
        return self.backend.do(PtraceCore.PTRACE_ATTACH, pid)

    def traceme(self):
        return self.backend.do(PtraceCore.PTRACE_TRACEME, os.getpid())

    def detach(self, pid, sig):
        return self.backend.do(PtraceCore.PTRACE_DETACH, pid, data=sig)

    def singlestep(self, pid, sig=None):
        return self.backend.do(PtraceCore.PTRACE_SINGLESTEP, pid, data=sig)

    def cont(self, pid, sig=None):
        return self.backend.do(PtraceCore.PTRACE_CONT, pid, data=sig)

    def syscall(self, pid, sig=None):
        return self.backend.do(PtraceCore.PTRACE_SYSCALL, pid, data=sig)

    def peekdata(self, pid, addr):
        return self.get(pid, addr)

    def peektext(self, pid, addr):
        return self.get(pid, addr)

    def pokedata(self, pid, addr, data):
        return self.set(pid, addr, data)

    def poketext(self, pid, addr, data):
        return self.set(pid, addr, data)

    def pokeuser(self, pid, addr, data):
        return self.backend.do(PtraceCore.PTRACE_POKEUSER,  pid, addr, data)

    def peekuser(self, pid, addr):
        return self.backend.do(PtraceCore.PTRACE_PEEKUSER,  pid, addr, 0)

    def get(self, pid, addr):
        return self.backend.do(PtraceCore.PTRACE_PEEKTEXT,  pid, addr, 0)

    def set(self, pid, addr, data):
        return self.backend.do(PtraceCore.PTRACE_POKETEXT,  pid, addr, data)

    def kill(self, pid):
        return self.backend.do(PtraceCore.PTRACE_KILL,  pid)

    def getregisters(self, pid):
        sig = PtraceRawRegisters()
        ret=self.backend.do(PtraceCore.PTRACE_GETREGS,  pid, data=byref(regs))
        if ret < 0:
            ret = None
        else:
            ret = regs
        return ret

    def setregisters(self, pid, regs):
        return self.backend.do(PtraceCore.PTRACE_SETREGS,  pid, data=byref(regs))

    def getsiginfo(self, pid):
        sig = SignalInfo()
        ret=self.backend.do(PtraceCore.PTRACE_GETSIGINFO,  pid, data=byref(sig))
        if ret < 0:
            ret = None
        else:
            ret = sig
        return ret

    def setsiginfo(self, pid, sig):
        return self.backend.do(PtraceCore.PTRACE_SETSIGINFO,  pid, data=sig)

    def setoptions(self, pid, opt):
        return self.backend.do(PtraceCore.PTRACE_SETOPTIONS,  pid, data=opt)
    
    def follow(self, pid):
        opt =  PtraceCore.PTRACE_O_TRACEFORK | PtraceCore.PTRACE_O_TRACEVFORK | PtraceCore.PTRACE_O_TRACECLONE
        return self.setoptions(pid, opt)

    def settracesysgood(self, pid):
        opt = PtraceCore.PTRACE_O_TRACESYSGOOD
        return self.setoptions(pid, opt)

    def geteventmsg(self, pid):
        cpid = c_int()
        ret  = self.backend.do(PtraceCore.PTRACE_GETEVENTMSG,  pid, data=byref(cpid))
        if ret < 0:
            ret = None
        else:
            ret = cpid.value
        return ret

    def getchildpid(self, pid):
        return self.geteventmsg(pid)

class TracedProcess(object):
    tracer=None
    pid = 0

    def __init__(self, pid):
        self.tracer = PtraceCore()
        self.pid = pid

    def __getattribute__(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            return self.catchall(name)

    def catchall(self, name):
        return self.proxymethod(name)

    def proxymethod(self, name, *args, **kargs):
        return lambda *args, **kargs: object.__getattribute__(self.tracer, "%s" % name)(self.pid, *args, **kargs)

class ptrace(PtraceCore):
    pass
