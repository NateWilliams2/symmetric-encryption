#include <sodium.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

//Reades a key from a file determined by the trusted and principal names: /trusted/principal.key
int read_key_from_file(unsigned char* folder_name, size_t folder_name_size, unsigned char* principal, unsigned char* key){
	//constructing file path
	char keypath[MAX_NAME_SIZE+5] = "";
	strncat(keypath, (char*)folder_name, folder_name_size);
	strcat(keypath, "/");
	strcat(keypath, (char*)principal);
	strcat(keypath, ".key");
	
	//print path for debugging
	char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));
	//opening file
  FILE * keyfile = fopen(keypath, "r");
  if (keyfile == NULL) {
    perror("File Open Failed: ");
    return FILE_ACCESS_ERROR;
	}
	 /* Seek to the beginning of the file */
  fseek(keyfile, 0, SEEK_SET);
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
  fclose(keyfile);
  return 0;
}
