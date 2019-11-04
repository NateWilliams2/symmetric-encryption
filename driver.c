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
  unsigned char *principal = (unsigned char*)"bob";
  unsigned char *trusted = (unsigned char*)"sam";
  unsigned char sizes[2] = {3, 3};
  int request_size = 5+3+2;
  unsigned char request[request_size];
  generate_trusted_key(principal, trusted);
  session_key_request(principal, trusted, sizes, request);
  printf("Message request: %s\n", (char *)request);
  unsigned char p1msg[request_size + KEY_SIZE + TIME_SIZE];
  unsigned char p2msg[request_size + KEY_SIZE + TIME_SIZE];
  provide_session_key(request, p1msg, p2msg);
  printf("P1 msg: %s\n",(char *)p1msg);
  printf("P2 msg: %s\n",(char *)p2msg);
  return 0;
}
