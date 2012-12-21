  __constant const char padding_string[] = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41" \
                      	                   "\x64\x00\x4E\x56\xFF\xFA\x01\x08" \
		                           "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80" \
		                           "\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
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

__kernel void check_pdfs(constant const PDFParams* params, global password_t* passwords, global uint* out) {
  int id = get_global_id(0);
  out[id] = id + 1 + params->Length + passwords[id].size_bytes;
}
