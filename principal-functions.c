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

int provide_session_key(unsigned char *message, unsigned char *p1msg, unsigned char* p2msg){
  unsigned char session_key[KEY_SIZE];
  crypto_secretbox_keygen(session_key);
  unsigned char p1[MAX_NAME_SIZE];
  unsigned char p2[MAX_NAME_SIZE];
  time_t now = time(NULL);
  char time_buff[TIME_SIZE];
  strftime(time_buff, TIME_SIZE, "%Y-%m-%d %H:%M:%S", localtime(&now));

  int i=0;
  int msg_size = sizeof(message);
  for(int i = 0; message[i] != '%'; i++){
    memcpy(p1 + i, &message[i], 1);
  }
  i++;
  for(; message[i] != '%'; i++){
    memcpy(p1 + i, &message[i], 1);
  }

  memcpy(p1msg, message, msg_size);
  memcpy(p1msg + msg_size, session_key, KEY_SIZE);
  memcpy(p1msg + msg_size + KEY_SIZE, (unsigned char*)time_buff, TIME_SIZE);

  memcpy(p2msg, message, msg_size);
  memcpy(p2msg + msg_size, session_key, KEY_SIZE);
  memcpy(p2msg + msg_size + KEY_SIZE, (unsigned char*)time_buff, TIME_SIZE);
  printf((char *)p1msg);
  return 0;
}

//generates a session key request in request array: % + name of principal 1 + % + name of principal 2.
//Sizes[0] and sizes[1] contain the character length of principal_a and principal_b, respectively
int session_key_request(unsigned char *principal_a, unsigned char *principal_b, unsigned char *sizes, unsigned char *request){
  unsigned char *fmt = (unsigned char*)"%";
  int a = sizes[0];
  int b = sizes[1];
  memcpy(request, fmt, 1);
  memcpy(request + 1, principal_a, a);
  memcpy(request + 1 + a, fmt, 1);
  memcpy(request + 2 + a, principal_b, b);
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
  unsigned char *principal = (unsigned char*)"bob";
  unsigned char *trusted = (unsigned char*)"sam";
  unsigned char sizes[2] = {3, 3};
  int request_size = 5+3+2;
  unsigned char request[request_size];
  generate_trusted_key(principal, trusted);
  session_key_request(principal, trusted, sizes, request);
  printf("%s\n", (char *)request);
  unsigned char p1msg[request_size + KEY_SIZE + TIME_SIZE];
  unsigned char p2msg[request_size + KEY_SIZE + TIME_SIZE];
  provide_session_key(request, p1msg, p2msg);
  return 0;
}
