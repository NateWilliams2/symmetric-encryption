#include <sodium.h>
#include <string.h>
#include <time.h> 
#include <unistd.h>  
#include "trusted-functions.c"
#include "principal-functions.c"

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
#define REQUEST_SIZE MAX_NAME_SIZE*2 + 2
#define MESSAGE_LEN REQUEST_SIZE + KEY_SIZE + TIME_SIZE
#define CIPHERTEXT_LEN crypto_secretbox_MACBYTES + MESSAGE_LEN

int main(void){
  if (sodium_init() < 0) {
    perror("crypto library couldn't be initialized");
  }
  unsigned char *principal1 = (unsigned char*)"alice";
  size_t p1_size = 5;
  unsigned char *principal2 = (unsigned char*)"bob";
  size_t p2_size = 3;
  unsigned char *trusted = (unsigned char*)"sam";
  size_t t_size = 3;
  unsigned char request[REQUEST_SIZE]; 

  generate_trusted_key(principal1, trusted);
  generate_trusted_key(principal2, trusted);
  session_key_request(principal1, p1_size, principal2, p2_size, request);
  printf("Message request: %s\n", (char *)request);
  unsigned char p1msg[CIPHERTEXT_LEN + NONCE_SIZE];
  unsigned char p2msg[CIPHERTEXT_LEN + NONCE_SIZE];
  provide_session_key(request, p1msg, p2msg, trusted, t_size);
	int msg_verify_err = verify_session_key_message(p1msg, p2msg, principal1, p1_size, principal2, trusted);
	if (msg_verify_err != 0) {
		printf("Message verification error: %d\n", msg_verify_err);
	}
  return 0;
}

