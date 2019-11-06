#include <sodium.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

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

#define KEY_SIZE crypto_secretbox_KEYBYTES
#define MAX_NAME_SIZE 20
#define TIME_SIZE 20
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define REQUEST_SIZE MAX_NAME_SIZE*2 + 2
#define MESSAGE_LEN REQUEST_SIZE + KEY_SIZE + TIME_SIZE
#define CIPHERTEXT_LEN crypto_secretbox_MACBYTES + MESSAGE_LEN

//Reades a key from a file determined by the trusted and principal names: /trusted/principal.key
int read_key_from_file_ext(unsigned char* folder_name, size_t folder_name_size, unsigned char* principal, unsigned char* key){
	//constructing file path
  printf("getting key:\n");
	char keypath[MAX_NAME_SIZE+5] = "";
	strncat(keypath, (char*)folder_name, folder_name_size);
	strcat(keypath, "/");
	strcat(keypath, (char*)principal);
	strcat(keypath, ".key");
	
	//print path for debugging
	char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));
  printf("Current file path: %s/k:%s\n", cwd, keypath);
	//opening file
  FILE * keyfile = fopen(keypath, "r");
  if (keyfile == NULL) {
    perror("File Open Failed: ");
    return FILE_ACCESS_ERROR;
	}
	 /* Seek to the beginning of the file */
  fseek(keyfile, 0, SEEK_SET);
  printf("reading file:\n");
  if (fread(key, 1, KEY_SIZE, keyfile) != KEY_SIZE){
    if (feof(keyfile)){
    	printf("End of file was reached.\n");
    	}

		if (ferror(keyfile)){
		  printf("An error occurred.\n");
		  }
		fclose(keyfile);
		return FILE_ACCESS_ERROR;
  }
  printf("file read:\n");
  fclose(keyfile);
  return 0;
}

bool msg_is_null(unsigned char* msg){
	for (int i=0; i < CIPHERTEXT_LEN; i++){
		if (msg[i] != (unsigned char)'\0'){
			return false;
		}
	}
	return true;
	
}

int verify_session_key_message(unsigned char* p1msg, unsigned char* p2msg, unsigned char* p1, size_t p1_size, unsigned char* p2, unsigned char* trusted){
	if (msg_is_null(p1msg) || msg_is_null(p2msg)){
		return NULL_MSG_ERROR;
	}
	unsigned char nonce[NONCE_SIZE];
	unsigned char msg_dec[MESSAGE_LEN];
	memcpy(nonce, p1msg + CIPHERTEXT_LEN, NONCE_SIZE);
	unsigned char key[KEY_SIZE];
	int read_key = read_key_from_file_ext(p1, p1_size, trusted, key);
	if (read_key != 0){
		return read_key;
	}
	if (crypto_secretbox_open_easy(msg_dec, p1msg, CIPHERTEXT_LEN, nonce, key) != 0) {
    return DECRYPTION_ERROR;
	}
	printf("Decrypted message: %s%s\n", (char*)msg_dec, (char*)msg_dec + REQUEST_SIZE);
	return 0;
}

//generates a session key request in request array: name of principal 1 + % + name of principal 2 + %
//Sizes[0] and sizes[1] contain the character length of principal_a and principal_b, respectively
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

