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
#define MESSAGE_LEN REQUEST_SIZE + KEY_SIZE + TIME_SIZE
#define CIPHERTEXT_LEN crypto_secretbox_MACBYTES + MESSAGE_LEN

//Reades a key from a file determined by the trusted and principal names: /trusted/principal.key
int read_key_from_file(unsigned char* folder_name, size_t folder_name_size, unsigned char* principal, unsigned char* key){
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
  if (fread(key, KEY_SIZE, 1, keyfile) != KEY_SIZE){
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

//provides a session key for the encypted exchange: {A, B, Kab, T}Kas and {A, B, Kab, T}Kbs
int provide_session_key(unsigned char *message, unsigned char *p1msg, unsigned char* p2msg, unsigned char* trusted, size_t t_size){
  //buffers to hold principal names
  unsigned char p1[MAX_NAME_SIZE];
  unsigned char p2[MAX_NAME_SIZE];

  //storing current time as unsigned chars
  time_t now = time(NULL);
  char time_buff[TIME_SIZE];
  strftime(time_buff, TIME_SIZE, "%Y-%m-%d %H:%M:%S", localtime(&now));

  //copying principal names from message into p1 and p2
  int i=0;
  printf("copying p 1:\n");
  for(; message[i] != (unsigned char)'%'; i++){
    memcpy(p1 + i, &message[i], 1);
  }
  i++;
  int j = 0; //contains index of p2, i-len(p1)
  printf("copying p 2:\n");
  for(; message[i] != '%'; i++){
    memcpy(p2 + j, &message[i], 1);
    j++;
  }
  
  //reading keys
  unsigned char p1_key[KEY_SIZE];
  unsigned char p2_key[KEY_SIZE];
	read_key_from_file(trusted, t_size, p1, p1_key);
	read_key_from_file(trusted, t_size, p2, p2_key);
	
	//generating session key
  unsigned char session_key[KEY_SIZE];
  crypto_secretbox_keygen(session_key);
  
  //constructing message
  printf("setting up encrption:\n");
  unsigned char msg_buff[MESSAGE_LEN];
  memcpy(msg_buff, message, REQUEST_SIZE);
  memcpy(msg_buff + REQUEST_SIZE, session_key, KEY_SIZE);
  memcpy(msg_buff + REQUEST_SIZE + KEY_SIZE, (unsigned char*)time_buff, TIME_SIZE);

	printf("Message constructed: %s%s\n", (char*)msg_buff, (char*)msg_buff + REQUEST_SIZE);
  
	//encrypting messages
	unsigned char nonce[NONCE_SIZE];
  randombytes_buf(nonce, NONCE_SIZE);
  crypto_secretbox_easy(p1msg, msg_buff, MESSAGE_LEN, nonce, p1_key);
  memcpy(p1msg + CIPHERTEXT_LEN, nonce, NONCE_SIZE);

  randombytes_buf(nonce, NONCE_SIZE);
  crypto_secretbox_easy(p2msg, msg_buff, MESSAGE_LEN, nonce, p2_key);
  memcpy(p2msg + CIPHERTEXT_LEN, nonce, NONCE_SIZE);

  return 0;
}



