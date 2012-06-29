ptracemodule
============

yet another python module around ptrace()

Why another python module around ptrace() ?
===========================================


I wrote this module because I was tired of the module available in
subterfugue : this module is not maintained anymore and it lacks
several features. Why not submit a patch ? Mainly because ptracemodule
is a C wrapper and I don't want to waste my time resolving unmet build
dependencies or tools, etc.

Furthermore, it's a simple wrapper Python to C : it's really not
written with OOP paradigms in mind and there is no abstraction
layer. That was my main problem because I wanted to use the ptrace
interface without using the ptrace() syscall. Sounds silly?

Not really, think about emulating ptrace for hostile binaries/crackmes
for instance! Thus PtraceCore module is not tied to ptrace(): you can
use the [utrace*() interface](http://lwn.net/Articles/224772/),
Solaris /proc debugging stuff, or even the Microsoft Windows
mechanisms.

Objectives
==========

The goal of the module is to be fast to deploy, just drop the
ptrace.py into the working directory and just enjoy! No need to
compile anything if you want.

How does it works?
==================

This module uses intensively
the [Ctypes module](http://docs.python.org/lib/module-ctypes.html) to
use the ptrace() syscall available in the Libc.

Portability
===========

This module has only be tested on Linux 2.6. It should be quite easy
to port the interface on other plateforms. You just have to implement
three functions, see the PtraceCoreCtypes class for instance.

Similar projects
================

There are now a few similar projects which are a lot more complete:

  - [python-ptrace by Victor Stinner](http://bitbucket.org/haypo/python-ptrace/wiki/Home)
  - [subterfugue](http://subterfugue.org/)
  - [ptrace(2) by SlideInc](http://github.com/slideinc/ptrace)


