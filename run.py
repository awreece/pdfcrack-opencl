#!/usr/bin/python

import itertools
from optparse import OptionParser
from pythonpdfcracker import PythonPDFCracker
from openclpdfcracker import OpenCLPDFCracker

if __name__ == "__main__":
  parser = OptionParser()
  parser.add_option("-i", "--input", dest="input_filename", default="file.pdf")
  parser.add_option("--use-gpu", action="store_true", dest="gpu", default=False)
  (options, args) = parser.parse_args()

  try:
    if options.gpu:
      c = OpenCLPDFCracker(filename=options.input_filename)
    else:
      c = PythonPDFCracker(filename=options.input_filename)
  except NoEncryptionError:
    exit(-1)

  charset = string.letters + string.digits
  c.auth_owners(itertools.chain(itertools.imap(
    lambda n: itertools.product(charset, n),
    itertools.count())))
    
