#!/usr/bin/python

import pyopencl as cl
import numpy as np
import ctypes
import md5
from pdfcracker import PDFCracker
from Crypto.Cipher import ARC4

MAX_WORDS_PER_ROUND = 1000
mf = cl.mem_flags

class OpenCLPDFCracker(PDFCracker):
  def __init__(self, data=None, filename=None):
    super(OpenCLPDFCracker, self).__init__(data, filename)

    # Init OpenCL shits
    self.ctx = cl.create_some_context()
    self.queue = cl.CommandQueue(self.ctx)

    src = reduce(lambda accum, filename: accum + open(filename, "r").read(), 
	         ["pdf.cl", "md5.cl", "rc4.cl", "buf.cl"], "")
    self.prg = cl.Program(self.ctx, src).build()
    consts = np.array([(self.P, self.Length, self.FileID, self.U, self.O)],
                      dtype=[("P","i4"), 
                             ("Length", np.uint32), 
		             ("FileID", "a16"),
			     ("U", "a32"),
			     ("O", "a32")])
    self.params = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, 
	                    hostbuf=consts)

  def auth_owners_round(self, passwords):
    assert len(passwords) <= MAX_WORDS_PER_ROUND

    in_array = np.array([(len(password), password) for password in passwords],
                        dtype=[("size_bytes", 'i4'), ("password","a28")])
    in_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
	               hostbuf=in_array)
    out_array = np.zeros(len(passwords), dtype='i4')
    out_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, out_array.nbytes)

    self.prg.check_pdfs(self.queue, in_array.shape, None, 
	                self.params, in_buf, out_buf)
    cl.enqueue_copy(self.queue, out_array, out_buf).wait()

    for (i, valid) in enumerate(out_array):
      print valid
      if valid == 1:
	return passwords[i]
    return None


  def auth_owners(self, passwords):
    while len(passwords) > 0:
      if len(passwords) > MAX_WORDS_PER_ROUND:
	round_passwords = passwords[:MAX_WORDS_PER_ROUND]
	passwords = passwords[MAX_WORDS_PER_ROUND:]
      else:
	round_passwords = passwords
	passwords = []
      ret = self.auth_owners_round(round_passwords)
      if ret is not None:
	return ret
    return None

  def auth_users(self, passwords):
    pass

cracker = OpenCLPDFCracker(filename="moop.pdf")

print cracker.auth_owners(["", "fish", "tomato", "CookiesAndCreams"])
