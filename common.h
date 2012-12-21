#ifndef COMMON_H
#define COMMON_H

typedef struct {
  int P;
  uint Length;
  char FileID[16];
  char U[32];
  char O[32];
} PDFParams;

#define MAX_PASSWORD_LENGTH 28
typedef struct {
  char password[MAX_PASSWORD_LENGTH];
  uint size_bytes;
} password_t;

#endif
