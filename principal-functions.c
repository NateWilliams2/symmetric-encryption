#include <sodium.h>
#include <string.h>
#include <time.h>

#define OUTPUT_ERROR  1
#define INPUT_ERROR  2
#define FILE_CLOSE_ERROR  3
#define FILE_ACCESS_ERROR  4
#define FILENAME_CONSTRUCTION_ERROR  5
#define TERMINAL_CONTROL_ERROR  6
#define CRYPTO_INITIALIZATION_ERROR  7
#define KEY_GENERATION_ERROR  8
#define ENCRYPTION_ERROR  9
#define DECRYPTION_ERROR  10

#define KEY_SIZE crypto_secretbox_KEYBYTES
#define MAX_NAME_SIZE 20
#define TIME_SIZE 20
#define NONCE_SIZE crypto_secretbox_NONCEBYTES

//generates a session key request in request array: name of principal 1 + % + name of principal 2 + %
//Sizes[0] and sizes[1] contain the character length of principal_a and principal_b, respectively
int session_key_request(unsigned char *principal_a, unsigned char *principal_b, unsigned char *sizes, unsigned char *request){
  unsigned char *fmt = (unsigned char*)"%";
  int a = sizes[0];
  int b = sizes[1];
  memcpy(request, principal_a, a);
  memcpy(request + a, fmt, 1);
  memcpy(request + a + 1, principal_b, b);
  memcpy(request + a + b + 1, fmt, b);
  return 0;
}
