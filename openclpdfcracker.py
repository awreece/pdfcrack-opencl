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
    self.ctx = cl.create_some_context()
    self.queue = cl.CommandQueue(self.ctx)
    self.prg = cl.Program(self.ctx, open("pdf.cl","r").read()).build()
    consts = np.array([(-1, 17, "fileid", "userbytes", "ownerbytes")], 
                         dtype=[("P","i4"), 
                                ("Length", np.uint32), 
			        ("FileID", "a16"),
			        ("U", "a32"),
			        ("O", "a32")])
    self.params = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=consts)
    self.out_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, 4 * MAX_WORDS_PER_ROUND)
    self.in_array = np.zeros(MAX_WORDS_PER_ROUND, 
                             dtype=[("password","a28"), ("size_bytes", 'i4')])

  def auth_owners_round(self, passwords):
    assert len(passwords) <= MAX_WORDS_PER_ROUND

    # Copy the passwords into the input array.
    for (i, password) in enumerate(passwords):
      self.in_array[i] = (password, len(password))

    in_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
	               hostbuf=self.in_array)
    out_array = np.zeros(MAX_WORDS_PER_ROUND, dtype='i4')

    # Only launch len(passwords) threads.
    self.prg.check_pdfs(self.queue, (len(passwords),) , None, 
	                self.params, in_buf, self.out_buf)
    cl.enqueue_copy(self.queue, out_array, self.out_buf).wait()

    # Iterate over passwords since its the right length.
    for (i, password) in enumerate(passwords):
      print out_array[i]
      if out_array[i] == 1:
	return password
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

cracker = OpenCLPDFCracker(data = {
  "V": 0,
  "R": 3,
  "P": -1,
  "Length": 17,
  "FileID": "fileid",
  "U": "userbytes",
  "O": "ownerbytes",
  })

print cracker.auth_owners(["fish", "tomato"])
