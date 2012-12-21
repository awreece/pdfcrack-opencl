#!/usr/bin/python

# Copyright 2012 Alex Reece

import pyopencl as cl
import numpy as np
import ctypes
import itertools
import md5
import time
from pdfcracker import PDFCracker
from Crypto.Cipher import ARC4

MAX_WORDS_PER_ROUND = 1024*64
mf = cl.mem_flags

# From http://docs.python.org/2/library/itertools.html
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

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
    self.password_dtype = [("size_bytes", 'i4'), ("password","a60")]

  def auth_owners_round(self, passwords, userpass_buf=None):
    assert len(passwords) <= MAX_WORDS_PER_ROUND

    in_array = np.array([(len(password), password) for password in passwords],
                        dtype=self.password_dtype)
    in_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
	               hostbuf=in_array)
    out_array = np.zeros(len(passwords), dtype=np.uint32)
    out_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, out_array.nbytes)

    if userpass_buf is not None:
      self.prg.check_pdfs_known_user(self.queue, in_array.shape, None, 
	  self.params, userpass_buf, in_buf, out_buf)
    else:
      self.prg.check_pdfs(self.queue, in_array.shape, None, 
	  self.params, in_buf, out_buf)
    cl.enqueue_copy(self.queue, out_array, out_buf).wait()

    for (i, valid) in enumerate(out_array):
      if valid == 1:
	return passwords[i]
    return None


  def auth_owners(self, passwords, userpass=None):
    userpass_buf = None
    if userpass is not None:
	userpass_arr = np.array([(len(userpass), userpass)], 
	                        dtype=self.password_dtype)
        userpass_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, 
	                    hostbuf=userpass_arr)

    for round_passwords in grouper(MAX_WORDS_PER_ROUND, passwords, ''):
      start_time = time.clock()
      ret = self.auth_owners_round(round_passwords, userpass_buf=userpass_buf)
      if ret is not None:
	return ret
      if self.verbose:
      	print "Round of passwords started from %s, " \
	      "cracking %.2f passwords/s, %.2f bytes/s" % (
		  round_passwords[0], 
		  MAX_WORDS_PER_ROUND / (time.clock() - start_time), 
		  MAX_WORDS_PER_ROUND * 64 / (time.clock() - start_time))

    return None

  def auth_users(self, passwords):
    unimplemented = False
    assert unimplemented
