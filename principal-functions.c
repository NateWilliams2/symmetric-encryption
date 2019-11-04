#include <sodium.h>
#include <string.h>

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
#define MAX_NAME_SIZE 100
#define FMT_DELINIATION_SIZE 10


int session_key_request(unsigned char *principal_a, unsigned char *principal_b, unsigned char *request){
  unsigned char *formata = (unsigned char*)"PRINCIPAL1";
  unsigned char *formatb = (unsigned char*)"PRINCIPAL2";
  int a = FMT_DELINIATION_SIZE;
  int b = sizeof(principal_a);
  int c = FMT_DELINIATION_SIZE;
  int d = sizeof(principal_b);
  memcpy(request, formata, a);
  memcpy(request + a, principal_a, b);
  memcpy(request + a + b, formatb, c);
  memcpy(request + a + b + c, principal_b, d);
  return 0;
}

int generate_trusted_key(unsigned char *principal, unsigned char *trusted){
  unsigned char key[KEY_SIZE];
  crypto_secretbox_keygen(key);
  char principal_path[MAX_NAME_SIZE*2+5];
  strcpy(principal_path, (char*)principal);
  strcat(principal_path, "/");
  strcat(principal_path, (char*)trusted);
  strcat(principal_path, ".key");
  FILE * principal_file = fopen(principal_path, "w");
  if (fwrite(key, 1, KEY_SIZE, principal_file) != KEY_SIZE) {
    perror("Unable to write the key");
    return OUTPUT_ERROR;
  }
  char trusted_path[MAX_NAME_SIZE*2+5];
  strcpy(trusted_path, (char*)trusted);
  strcat(trusted_path, "/");
  strcat(trusted_path, (char*)principal);
  strcat(trusted_path, ".key");
  FILE * trusted_file = fopen(trusted_path, "w");
  if (fwrite(key, 1, KEY_SIZE, trusted_file) != KEY_SIZE) {
    perror("Unable to write the key");
    return OUTPUT_ERROR;
  }
  return 0;
}

int main(void){
  if (sodium_init() < 0) {
    perror("crypto library couldn't be initialized");
  }
  unsigned char * principal = (unsigned char*)"alice";
  unsigned char * trusted = (unsigned char*)"sam";
  unsigned char request[sizeof(principal)+sizeof(trusted)+FMT_DELINIATION_SIZE*2];
  generate_trusted_key(principal, trusted);
  session_key_request(principal, trusted, request);
  printf("%s\n", (char *)request);
  return 0;
}
