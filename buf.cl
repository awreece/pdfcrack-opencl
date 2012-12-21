#include "common.h"

#define make_buf_append(address_space)					    \
void buf_append_##address_space(buffer_t* buf,				    \
			       address_space const char* data, uint len) {  \
  uint i;								    \
  for (i = 0; i < len; i++) {						    \
    buf->buffer[buf->size + i] = data[i];				    \
  }									    \
  buf->size = buf->size + len;						    \
}									  

make_buf_append(private)
make_buf_append(constant)

void buf_init(buffer_t* buf, const char* data, uint len) {
  uint i;
  for (i = 0; i < len; i++) {
    buf->buffer[i] = data[i];
  }
  buf->size = len;
}

void md5_buffer(const buffer_t* in, buffer_t* out) {
  md5(in->buffer, in->size, (uint*) out->buffer);
  out->size = 16;
}

void rc4_init_buffer(rc4_state_t* const state, const buffer_t* key) {
  rc4_init(state, key->buffer, key->size);
}

void rc4_crypt_buffer(rc4_state_t* const state, const buffer_t* in, buffer_t* out) {
  rc4_crypt(state, in->buffer, out->buffer, in->size);
  out->size = in->size;
}
