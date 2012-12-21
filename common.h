// Copyright 2012 Alex Reece

#ifndef COMMON_H
#define COMMON_H

#define OWNER_BYTES_LEN 32
#define USER_BYTES_LEN 32
#define FILEID_BYTES_LEN 16

typedef struct {
  int P;
  uint Length;
  char FileID[FILEID_BYTES_LEN];
  char U[USER_BYTES_LEN];
  char O[OWNER_BYTES_LEN];
} PDFParams;

#define MAX_BUFFER_LENGTH (128 - sizeof(uint))
#define MAX_PASSWORD_LENGTH (64-sizeof(uint))
typedef struct {
  uint size_bytes;
  char password[MAX_PASSWORD_LENGTH];
} password_t;

typedef struct {
  uint v[4];
} password_hash_t;

typedef struct {
  uint size;
  char buffer[MAX_BUFFER_LENGTH];
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
void rc4_crypt_buffer(const buffer_t* key, const buffer_t* in, buffer_t* out);


void buf_append_private(buffer_t* buf, const char* data, uint len);
void buf_append_constant(buffer_t* buf, constant const char* data, uint len);
void buf_init(buffer_t* buf, const char* data, uint len);
void buf_xorall(buffer_t* buf, uchar byte);
int buf_eq(const buffer_t* a, const buffer_t* b);

#endif
