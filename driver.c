#define _XOPEN_SOURCE

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
#define KEY_REQUEST_LEN REQUEST_SIZE + KEY_SIZE + TIME_SIZE
#define KEY_CIPHERTEXT_LEN crypto_secretbox_MACBYTES + KEY_REQUEST_LEN
#define MESSAGE_LEN 256
#define MESSAGE_CIPHERTEXT_LEN crypto_secretbox_MACBYTES + MESSAGE_LEN

int main(void){
  if (sodium_init() < 0) {
    perror("crypto library couldn't be initialized");
    return CRYPTO_INITIALIZATION_ERROR;
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
  unsigned char p1msg[KEY_CIPHERTEXT_LEN + NONCE_SIZE];
  unsigned char p2msg[KEY_CIPHERTEXT_LEN + NONCE_SIZE];
  unsigned char session_key[KEY_SIZE];
  provide_session_key(request, p1msg, p2msg, trusted, t_size);
	int msg_verify_err = verify_session_key_message(p1msg, p2msg, principal1, p1_size, principal2, p2_size, trusted, session_key);
	if (msg_verify_err != 0) {
		printf("Message verification error: %d\n", msg_verify_err);
	}
	printf("Message verified\n");
	
	unsigned char message_enc[MESSAGE_CIPHERTEXT_LEN + NONCE_SIZE];
	int encrypt_err = encrypt_and_send_message(session_key, (unsigned char*)"simus", 5, message_enc);
	if (encrypt_err != 0){
		return encrypt_err;
	}
	printf("Message encrypted\n");
	
	unsigned char message_dec[MESSAGE_LEN];
	int receive_err = receive_and_decrypt_message(p2msg, message_enc, message_dec, principal1, p1_size, principal2, p2_size, trusted, t_size);
	if (receive_err != 0){
		return receive_err;
	}
	printf("Final Decrypted message: %s\n", (message_dec));
  return 0;
}

