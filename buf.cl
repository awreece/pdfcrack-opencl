#include "common.h"

void buf_append(buffer_t* buf, const char* data, uint len) {
  uint i;
  for (i = 0; i < len; i++) {
    buf->buffer[buf->size + i] = data[i];
  }
  buf->size = buf->size + len;
}

void buf_init(buffer_t* buf, const char* data, uint len) {
  uint i;
  for (i = 0; i < len; i++) {
    buf->buffer[i] = data[i];
  }
  buf->size = len;
}
