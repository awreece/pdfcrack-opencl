#!/usr/bin/python

import pyopencl as cl
import numpy
import ctypes
import md5
from pdfcracker import PDFCracker

class OpenCLPDFCracker(PDFCracker):
  def __init__(self, data=None, filename=None):
    super(PythonPDFCracker, self).__init__(data, filename)
    self.ctx = cl.create_some_context()
    self.queue = cl.CommandQueue(ctx)
    self.prg = cl.Program(ctx, open("md5.cl","r").read()).build()

a = "The quick brown fox jumps over the lazy dog. \x00 No really, it really fucking jumped over the lazy fucking dog. Now I'm using curse words just to make this shits longer."

ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx)

mf = cl.mem_flags
a_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf = a)
dest_buf = cl.Buffer(ctx, mf.WRITE_ONLY, 16)

prg = cl.Program(ctx, open("md5.cl","r").read()).build()

prg.md5(queue, (1,), None, numpy.uint32(len(a)), a_buf, dest_buf)

b = ctypes.create_string_buffer(16)
cl.enqueue_copy(queue, b, dest_buf).wait()

gpu_hash = "".join(b)
cpu_hash = md5.new(a).digest()

print gpu_hash.encode('hex'), cpu_hash.encode('hex')
assert cpu_hash == gpu_hash
