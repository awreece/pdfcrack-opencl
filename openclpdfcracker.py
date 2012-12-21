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


ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx)

a = numpy.array([("fish", 4), ("cow", 3)], 
                dtype=[("password","a28"), ("size_bytes", 'i4')])
b = numpy.zeros(2, dtype='a16')

mf = cl.mem_flags
a_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=a)
dest_buf = cl.Buffer(ctx, mf.WRITE_ONLY, b.nbytes)

prg = cl.Program(ctx, open("md5.cl","r").read()).build()

prg.do_md5s(queue, a.shape, None, a_buf, dest_buf)

cl.enqueue_copy(queue, b, dest_buf).wait()

print " ".join(map(lambda buf: "".join(buf).encode('hex'), b))
