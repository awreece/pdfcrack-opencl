#!/usr/bin/python

import itertools
from optparse import OptionParser
from pythonpdfcracker import PythonPDFCracker
from openclpdfcracker import OpenCLPDFCracker
from pdfcracker import NoEncryptionError
from string import strip

import string

if __name__ == "__main__":
  parser = OptionParser()
  parser.add_option("-i", "--input_filename", dest="input_filename", default="file.pdf")
  parser.add_option("--use-gpu", action="store_true", dest="gpu", default=False)
  parser.add_option("-u", "--user_password", dest="userpass")
  (options, args) = parser.parse_args()

  try:
    if options.gpu:
      c = OpenCLPDFCracker(filename=options.input_filename)
    else:
      c = PythonPDFCracker(filename=options.input_filename)
  except NoEncryptionError:
    exit(-1)

  charset = string.letters + string.digits

  def generate_dict_words(args):
    for filename in args:
      for line in open(filename):
	yield strip(line, "\n")


  generate_all_words = itertools.imap(lambda w: "".join(w), 
			 itertools.chain.from_iterable(
			   itertools.imap(lambda n: itertools.product(charset, repeat=n),
			                  itertools.count())))

  print c.auth_owners(itertools.chain(generate_dict_words(args),
                                      generate_all_words),
		      userpass=options.userpass)
    
