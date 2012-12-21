#include "common.h"

__constant const char padding_string[] = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41" \
                      	                 "\x64\x00\x4E\x56\xFF\xFA\x01\x08" \
		                         "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80" \
		                         "\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

static void repeat_md5(buffer_t* buf) {
  buffer_t local_buf;

  int i;
  for (i = 0; i < 25; i++) {
    md5_buffer(buf, &local_buf);
    md5_buffer(&local_buf, buf);
  }
}

static void compute_encryption_key(constant const PDFParams* params, const password_t* password, buffer_t* out) {
  buffer_t md5_buf;

  buf_init(&md5_buf, password->password, password->size_bytes);
  buf_append_constant(&md5_buf, padding_string, 32 - password->size_bytes);
  buf_append_constant(&md5_buf, params->O, OWNER_BYTES_LEN);
  buf_append_constant(&md5_buf, (constant char*) &params->P, sizeof(int));
  buf_append_constant(&md5_buf, params->FileID, FILEID_BYTES_LEN);
  md5_buffer(&md5_buf, out);
  // TODO(awreece) if R != 3
  repeat_md5(out);
  out->size = params->Length / 8;
}

static void repeated_rc4_encrypt(buffer_t* key, buffer_t* msg) {
  uchar i;
  buffer_t local_buf;
  for (i = 0; i < 20; i += 2) {
    buf_xorall(key, i);
    rc4_crypt_buffer(key, msg, &local_buf);
    buf_xorall(key, i ^ (i+1));
    rc4_crypt_buffer(key, &local_buf, msg);
    buf_xorall(key, i + 1);
  }
}

static void repeated_rc4_decrypt(buffer_t* key, buffer_t* msg) {
  uchar i;
  buffer_t local_buf;
  for (i = 0; i < 20; i += 2) {
    buf_xorall(key, 20 - 1 - i);
    rc4_crypt_buffer(key, msg, &local_buf);
    buf_xorall(key, (20 - 1 - i) ^ (20 - i));
    rc4_crypt_buffer(key, &local_buf, msg);
    buf_xorall(key, 20 - i);
  }
}

static void compute_owner_key(constant const PDFParams* params, const password_t* password, buffer_t* out) {
  buffer_t md5_buf;
  buf_init(&md5_buf, password->password, password->size_bytes);
  buf_append_constant(&md5_buf, padding_string, 32 - password->size_bytes);
  md5_buffer(&md5_buf, out);
  // TODO(awreece) if R != 3
  repeat_md5(out);
  out->size = params->Length / 8;
}

static void compute_user_bytes(constant const PDFParams* params, const password_t* password, buffer_t* out) {
  buffer_t key;
  compute_encryption_key(params, password, &key);
  
  buffer_t md5_buf;
  md5_buf.size = 0;
  buf_append_constant(&md5_buf, padding_string, 32);
  buf_append_constant(&md5_buf, params->FileID, FILEID_BYTES_LEN);
  md5_buffer(&md5_buf, out);

  repeated_rc4_encrypt(&key, out);
  // Rather than padding arbitrarily, we will truncate.
  out->size = 16;
}

static int check_user_pass(constant const PDFParams* params, const password_t* password) {
  buffer_t maybe_u_bytes;
  compute_user_bytes(params, password, &maybe_u_bytes);

  uint i;
  for (i = 0; i < maybe_u_bytes.size; i++) {
    if (params->U[i] != maybe_u_bytes.buffer[i]) {
      return 0;
    }
  }
  return 1;
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
