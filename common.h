#ifndef COMMON_H
#define COMMON_H

typedef struct {
  int P;
  uint Length;
  char FileID[16];
  char U[32];
  char O[32];
} PDFParams;

#define MAX_BUFFER_LENGTH (128 - sizeof(uint))
#define MAX_PASSWORD_LENGTH 28
typedef struct {
  char password[MAX_PASSWORD_LENGTH];
  uint size_bytes;
} password_t;

typedef struct {
  uint v[4];
} password_hash_t;

typedef struct {
  char buffer[MAX_BUFFER_LENGTH];
  uint size;
} buffer_t;

void md5(const char* restrict msg, uint length_bytes, uint* restrict out);
void md5_buffer(const buffer_t* in, buffer_t* out);

typedef struct {
  uchar	perm[256];
  uchar	index1;
  uchar	index2;
} rc4_state_t;

void rc4_init(rc4_state_t* const state, const char* key, int keylen);

void rc4_crypt(rc4_state_t* const state, const char* in, char* out, int buflen);


void buf_append_private(buffer_t* buf, const char* data, uint len);
void buf_append_constant(buffer_t* buf, constant const char* data, uint len);
void buf_init(buffer_t* buf, const char* data, uint len);

#endif
