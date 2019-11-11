#define _XOPEN_SOURCE

#include <sodium.h>
#include <string.h>
#include <time.h> 
#include <unistd.h>  
#include "trusted-functions.h"
#include "principal-functions.h"

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

	//INITIALIZING CRYPTO
  if (sodium_init() < 0) {
    perror("crypto library couldn't be initialized");
    return CRYPTO_INITIALIZATION_ERROR;
  }

	//DEFINING USER NAMES
  unsigned char *principal1 = (unsigned char*)"alice";
  size_t p1_size = 5;
  unsigned char *principal2 = (unsigned char*)"bob";
  size_t p2_size = 3;
  unsigned char *trusted = (unsigned char*)"sam";
  size_t t_size = 3;

	//ALICE: GENERATES KEYS WITH SAM
	printf("Alice initiating keygen request with sam...\n");
  unsigned char request[REQUEST_SIZE]; 
  int key_gen_err = generate_trusted_key(principal1, trusted);
	if (key_gen_err != 0){
		printf("Key Gen error: %d\n", key_gen_err);
		return key_gen_err;
	}

	//BOB: GENERATES KEYS WITH SAM
	printf("Bob initiating keygen request with sam...\n");
  key_gen_err = generate_trusted_key(principal2, trusted);
	if (key_gen_err != 0){
		printf("Key Gen error: %d\n", key_gen_err);
		return key_gen_err;
	}

	//ALICE TO SAM: SESSION KEY REQUEST A->S: A,B
	printf("Alice requesting session key with bob from sam...\n");
  int session_key_err = session_key_request(principal1, p1_size, principal2, p2_size, request);
	if (session_key_err != 0){
		printf("Session Key generation error: %d\n", session_key_err);
		return session_key_err;
	}

  unsigned char p1msg[KEY_CIPHERTEXT_LEN + NONCE_SIZE];
  unsigned char p2msg[KEY_CIPHERTEXT_LEN + NONCE_SIZE];
  unsigned char session_key[KEY_SIZE];

	//SAM TO ALICE: PROVIDE SESSION KEY S->A: {A, B, Kab, T}Kas, {A, B, Kab, T}Kbs
	printf("Sam sending session key to alice...\n");
  int provide_key_err = provide_session_key(request, p1msg, p2msg, trusted, t_size);
	if (provide_key_err != 0) {
		printf("Providing key error: %d\n", provide_key_err);
		return provide_key_err;
	}

	//ALICE: VERIFY SESSION KEY MESSAGE FROM SAM
	printf("Alice verifying session key from sam...\n");
	int msg_verify_err = verify_session_key_message(p1msg, p2msg, principal1, p1_size, principal2, p2_size, trusted, session_key);
	if (msg_verify_err != 0) {
		printf("Message verification error: %d\n", msg_verify_err);
		return msg_verify_err;
	}
	
	//ALICE TO BOB: ENCRYPT AND SEND MESSAGE A->B: {A, B, Kab, T}Kbs, {M}Kab
	printf("Alice encrypting and sending message to Bob...\n");
	unsigned char message_enc[MESSAGE_CIPHERTEXT_LEN + NONCE_SIZE];
	int encrypt_err = encrypt_and_send_message(session_key, (unsigned char*)"Hello Bob, this is Alice. I'd like to chat! Call me ok?", 58, message_enc);
	if (encrypt_err != 0){
		printf("Encryption error: %d\n", encrypt_err);
		return encrypt_err;
	}
	
	//BOB: DECRYPT AND VERIFY MESSAGE
	printf("Bob decrypting and verifying message...\n");
	unsigned char message_dec[MESSAGE_LEN];
	int receive_err = receive_and_decrypt_message(p2msg, message_enc, message_dec, principal1, p1_size, principal2, p2_size, trusted, t_size);
	if (receive_err != 0){
		printf("Message receival error: %d\n", receive_err);
		return receive_err;
	}
	printf("Final Decrypted message: %s\n", (message_dec));
  return 0;
}

