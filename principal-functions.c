#define _XOPEN_SOURCE

#include <sodium.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "principal-functions.h"
#include "file-utility.h"

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
#define NULL_MSG_ERROR 11
#define NAME_EXTRACTION_ERROR 12
#define NAME_MATCH_ERROR 13
#define TIME_PARSE_ERROR 14
#define TIME_MATCH_ERROR 15
#define PADDING_ERROR 16

#define SECONDS_IN_DAY 86400
#define KEY_SIZE crypto_secretbox_KEYBYTES
#define MAX_NAME_SIZE 20
#define TIME_SIZE 20
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define REQUEST_SIZE MAX_NAME_SIZE*2 + 2
#define KEY_REQUEST_LEN REQUEST_SIZE + KEY_SIZE + TIME_SIZE
#define KEY_CIPHERTEXT_LEN crypto_secretbox_MACBYTES + KEY_REQUEST_LEN
#define MESSAGE_LEN 256
#define MESSAGE_CIPHERTEXT_LEN crypto_secretbox_MACBYTES + MESSAGE_LEN

//returns true if a given message of length msg_len is full of null-chars. returns false otherwise
int msg_is_null(unsigned char* msg, size_t msg_len){
	for (int i=0; i < msg_len; i++){
		if (msg[i] != (unsigned char)'\0'){
			return 0;
		}
	}
	return 1;
	
}

	//copies principal names from message into p1 and p2
int read_names_from_msg(unsigned char* message, unsigned char* p1, unsigned char* p2){
  int i=0;
  for(; message[i] != (unsigned char)'%'; i++){
    memcpy(p1 + i, &message[i], 1);
  }
  i++;
  int j = 0; //contains index of p2, i-len(p1)
  for(; message[i] != '%'; i++){
    memcpy(p2 + j, &message[i], 1);
    j++;
  }
	if (i < 2){
		return NAME_EXTRACTION_ERROR;
	}
	return 0;
}

//encrypts a given message with a given session key, saves that message with a nonce in message_enc
int encrypt_and_send_message(unsigned char* session_key, unsigned char* message, size_t msg_size, unsigned char* message_enc){
	//padding message
	size_t padded_len = 0;
	unsigned char padded_msg[MESSAGE_LEN];
	memcpy(padded_msg, message, msg_size);
	if (sodium_pad(&padded_len, padded_msg, msg_size, MESSAGE_LEN, MESSAGE_LEN) != 0) {
    return PADDING_ERROR;
	}
	
	//encrypting message
	unsigned char nonce[NONCE_SIZE];
  randombytes_buf(nonce, NONCE_SIZE);
  if (crypto_secretbox_easy(message_enc, padded_msg, MESSAGE_LEN, nonce, session_key) != 0){
  	return ENCRYPTION_ERROR;
  }
  memcpy(message_enc + MESSAGE_CIPHERTEXT_LEN, nonce, NONCE_SIZE);
  return 0;
}

//Verifies a session key message. Checks for null msg, decryption, name extraction, name matching, timestamp parsing, timestamp matching. Then writes decrypted session_key
int verify_session_key_message(unsigned char* p1msg, unsigned char* p2msg, unsigned char* p1, size_t p1_size, unsigned char* p2, size_t p2_size, unsigned char* trusted, unsigned char* session_key){

	//checking for null message
	if (msg_is_null(p1msg, KEY_REQUEST_LEN) == 1 || msg_is_null(p2msg, KEY_REQUEST_LEN) == 1){
		return NULL_MSG_ERROR;
	}
	unsigned char nonce[NONCE_SIZE];
	unsigned char msg_dec[KEY_REQUEST_LEN];
	memcpy(nonce, p1msg + KEY_CIPHERTEXT_LEN, NONCE_SIZE);
	unsigned char key[KEY_SIZE];
	int read_key = read_key_from_file(p1, p1_size, trusted, key);
	if (read_key != 0){
		return read_key;
	}
	
	//verifying decryption
	if (crypto_secretbox_open_easy(msg_dec, p1msg, KEY_CIPHERTEXT_LEN, nonce, key) != 0) {
    return DECRYPTION_ERROR;
	}

	unsigned char p1_dec[p1_size];
	unsigned char p2_dec[p2_size];
	//verifying name reading
	if (read_names_from_msg(msg_dec, p1_dec, p2_dec) != 0){
		return NAME_EXTRACTION_ERROR;
	}
	
	//verifying correct names
	if (memcmp(p1_dec, p1, p1_size) != 0 || memcmp(p2_dec, p2, p2_size) != 0){
		return NAME_MATCH_ERROR;
	}

	//verifying timestamp
	unsigned char time_dec_raw[TIME_SIZE];
	memcpy(time_dec_raw, msg_dec + REQUEST_SIZE + KEY_SIZE, TIME_SIZE);
	struct tm tm_dec;
	if (strptime((char*)time_dec_raw, "%Y-%m-%d %H:%M:%S", &tm_dec) == '\0'){
		return TIME_PARSE_ERROR;
	}
	time_t time_dec = mktime(&tm_dec);
	time_t now = time(NULL);
	double time_diff = difftime(now, time_dec);
	if(time_diff < 0 || time_diff > SECONDS_IN_DAY){
		return TIME_MATCH_ERROR;
	}

	memcpy(session_key, msg_dec + REQUEST_SIZE, KEY_SIZE);
	return 0;
}

//receives and decrypts a message. Checks for null msg, decryption, name extraction, name matching, timestamp parsing, timestamp matching. Extracts session key from key_message_enc and uses that key to decrypt ciphertext. writes decrypted message to message_dec. 
int receive_and_decrypt_message(unsigned char* key_message_enc, unsigned char* ciphertext, unsigned char* message_dec, unsigned char* p1, size_t p1_size, unsigned char* p2, size_t p2_size,unsigned char* trusted, size_t t_size){
	//checking for null message
	if (msg_is_null(key_message_enc, KEY_REQUEST_LEN) || msg_is_null(ciphertext, MESSAGE_LEN)){
		return NULL_MSG_ERROR;
	}
	unsigned char nonce[NONCE_SIZE];
	unsigned char key_message_dec[KEY_REQUEST_LEN];
	memcpy(nonce, key_message_enc + KEY_CIPHERTEXT_LEN, NONCE_SIZE);
	unsigned char trusted_key[KEY_SIZE];
	int read_key = read_key_from_file(p2, p2_size, trusted, trusted_key);
	if (read_key != 0){
		return read_key;
	}
	
	//verifying decryption
	if (crypto_secretbox_open_easy(key_message_dec, key_message_enc, KEY_CIPHERTEXT_LEN, nonce, trusted_key) != 0) {
    return DECRYPTION_ERROR;
	}

	unsigned char p1_dec[p1_size];
	unsigned char p2_dec[p2_size];
	//verifying name reading
	if (read_names_from_msg(key_message_dec, p1_dec, p2_dec) != 0){
		return NAME_EXTRACTION_ERROR;
	}
	
	//verifying correct names
	if (memcmp(p1_dec, p1, p1_size) != 0 || memcmp(p2_dec, p2, p2_size) != 0){
		return NAME_MATCH_ERROR;
	}

	//verifying timestamp
	unsigned char time_dec_raw[TIME_SIZE];
	memcpy(time_dec_raw, key_message_dec + REQUEST_SIZE + KEY_SIZE, TIME_SIZE);
	struct tm tm_dec;
	if (strptime((char*)time_dec_raw, "%Y-%m-%d %H:%M:%S", &tm_dec) == '\0'){
		return TIME_PARSE_ERROR;
	}
	time_t time_dec = mktime(&tm_dec);
	time_t now = time(NULL);
	double time_diff = difftime(now, time_dec);
	if(time_diff < 0 || time_diff > SECONDS_IN_DAY){
		return TIME_MATCH_ERROR;
	}
	
	//extracting session key
	unsigned char session_key[KEY_SIZE];
	memcpy(session_key, key_message_dec + REQUEST_SIZE, KEY_SIZE);
	
	//getting nonce from message
	memcpy(nonce, ciphertext + MESSAGE_CIPHERTEXT_LEN, NONCE_SIZE);
	
	//verifying message decryption
	if (crypto_secretbox_open_easy(message_dec, ciphertext, MESSAGE_CIPHERTEXT_LEN, nonce, session_key) != 0) {
    return DECRYPTION_ERROR;
	}
	return 0;
}

//generates a session key request in request array: name of principal 1 + % + name of principal 2 + %
int session_key_request(unsigned char *principal_1, size_t p1_size, unsigned char *principal_2, size_t p2_size, unsigned char *request){
  unsigned char *fmt = (unsigned char*)"%";
  memcpy(request, principal_1, p1_size);
  memcpy(request + p1_size, fmt, 1);
  memcpy(request + p1_size + 1, principal_2, p2_size);
  memcpy(request + p1_size + p2_size + 1, fmt, p2_size);
  return 0;
}

//generates a trusted key between a principal and a trusted third party, and stores that key in both the principal and trusted party directories
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
    fclose(principal_file);
    return OUTPUT_ERROR;
  }
  fclose(principal_file);
  char trusted_path[MAX_NAME_SIZE*2+5];
  strcpy(trusted_path, (char*)trusted);
  strcat(trusted_path, "/");
  strcat(trusted_path, (char*)principal);
  strcat(trusted_path, ".key");
  FILE * trusted_file = fopen(trusted_path, "w");
  if (fwrite(key, 1, KEY_SIZE, trusted_file) != KEY_SIZE) {
    perror("Unable to write the key");
    fclose(trusted_file);
    return OUTPUT_ERROR;
  }
  fclose(trusted_file);
  return 0;
}

