#include "common.h"

__constant const char padding_string[] = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41" \
                      	                   "\x64\x00\x4E\x56\xFF\xFA\x01\x08" \
		                           "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80" \
		                           "\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

static int check_user_pass(constant const PDFParams* params, const password_t* password) {
  return 0;
}

static int check_owner_pass(constant const PDFParams* params, const password_t* password) {
  return 0;
}

__kernel void check_pdfs(constant const PDFParams* params, const global password_t* passwords, global int* out) {
  int id = get_global_id(0);
  uint i;
  password_t password;
  for (i = 0; i < passwords[id].size_bytes; i++) {
    password.password[i] = passwords[id].password[i];
  }
  password.size_bytes = passwords[id].size_bytes;

  out[id] = check_owner_pass(params, &password);
  // TODO(awreece) Remove this: this is to suppress warnings.
  check_user_pass(params, &password);
}
