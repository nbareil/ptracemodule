#! /usr/bin/env python

from PtraceCore import *

class PtraceCoreTest:
    def __init__(self):
        p=PtraceCore()

    def run(self):
        print '-*-'*15 + ' TRACEME'
        #self.runTraceme()
        print '-*-'*15 + ' ATTACH'
        #self.runAttach()

    def runAttach(self):
        p = PtraceCore()
        pid = 11769
        addr = 0x7f827f34+4
        p.attach(pid)
        #regs = p.getregisters(pid)
        #print 'p.getregisters() => %s' % regs
        #print '*%#x = %#x' % (regs.ebp, p.get(pid, regs.ebp))
        #print '*%#x = %#x' % (regs.eip, p.get(pid, regs.eip))
        print '%#x' % (p.get(pid, addr))
        import struct
        p.set(pid, addr, 0x42424242)
        print '%#x' % (p.get(pid, addr))
        p.detach(pid)

    def testGetAndSet(self):
        p = PtraceCore()

    def runTraceme(self):
        p = PtraceCore()
        pid=os.fork()
        
        if pid > 0:
            print 'Child pid=%d stopped with status=%d' % (os.wait())
            print 'p.singlestep() => %d' % p.singlestep(pid)
            regs = p.getregisters(pid)
            print 'p.getregisters() => %s' % regs
            print '*%#x = %#x' % (regs.ebp, p.get(pid, regs.ebp))
            print '*%#x = %#x' % (regs.eip, p.get(pid, regs.eip))
            p.detach(pid)
            print '*'*80
            os.wait()
        else:
            p.traceme()
            os.execl('/bin/ls')

if __name__ == '__main__':
    test = PtraceCoreTest()
    test.run()
