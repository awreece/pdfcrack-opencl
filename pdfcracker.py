#!/usr/bin/python

from abc import ABCMeta, abstractmethod
import string, subprocess, time

class NoEncryptionError(Exception):
  pass

class PDFCracker(object):
  __metaclass__ = ABCMeta

  def auth_user(self, password):
    pass

  def auth_owner(self, password):
    pass

  @classmethod
  def parse_pdf_security_data(self, filename):
    def parse_int(line):
      return int(line[string.find(line, ":")+2:].strip())

    def parse_hex_string(line):
      return line[string.find(line, ":")+2:].strip().decode("hex")

    # TODO(awreece) There is a better way to do this.
    p = subprocess.Popen(["pdfcrack", filename, "--minpw=2", "--maxpw=1"],
                	 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    warning_line = p.stdout.readline()
    try:
      version_line = p.stdout.readline()
      handler_line = p.stdout.readline()
      V = parse_int(p.stdout.readline())
      R = parse_int(p.stdout.readline())
      P = parse_int(p.stdout.readline())
      Length = parse_int(p.stdout.readline())
      enc_meta_line = p.stdout.readline()
      # TODO(awreece) Actually, I think FileID can be any string. But if that
      # were the case, why does converting it to raw bytes work?
      FileID = parse_hex_string(p.stdout.readline())
      U = parse_hex_string(p.stdout.readline())
      O = parse_hex_string(p.stdout.readline())
      p.kill()
    except:
      print warning_line
      raise NoEncryptionError

    return {"V": V, "R": R, "P": P, "Length": Length, 
	    "FileID": FileID, "U": U, "O": O}

  def __init__(self, data=None, filename=None):
    if filename is not None:
      data = PDFCracker.parse_pdf_security_data(filename)

    self.V = data['V']
    self.R = data['R']
    self.P = data['P']
    self.Length = data['Length']
    self.FileID = data['FileID']
    self.U = data['U']
    self.O = data['O']

  @abstractmethod
  def auth_users(self, passwords):
    pass

  @abstractmethod
  def auth_owners(self, passwords):
    pass
