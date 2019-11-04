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

//provides a session key for the encypted exchange: {A, B, Kab, T}Kas and {A, B, Kab, T}Kbs
int provide_session_key(unsigned char *message, unsigned char *p1msg, unsigned char* p2msg){
  //setting up encryption, generating key
  unsigned char session_key[KEY_SIZE];
  unsigned char nonce[NONCE_SIZE];
  crypto_secretbox_keygen(session_key);

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
  //msg size is number of chars iterated over in loop
  int msg_size = i+1;

  //getting keys from principals


  //encrypting messages
  int plaintext_len = msg_size + KEY_SIZE + TIME_SIZE;
  unsigned char msg_buff[plaintext_len];

  randombytes_buf(nonce, NONCE_SIZE);
  //crypto_secretbox_easy(p1msg, msg_buff, plaintext_len, nonce, key);

  randombytes_buf(nonce, NONCE_SIZE);
  //crypto_secretbox_easy(p2msg, msg_buff, MESSAGE_LEN, nonce, key);


  memcpy(msg_buff, message, msg_size);
  memcpy(msg_buff + msg_size, session_key, KEY_SIZE);
  memcpy(msg_buff + msg_size + KEY_SIZE, (unsigned char*)time_buff, TIME_SIZE);



  printf("p1: %s\n", p1);
  printf("p2: %s\n", p2);
  printf("\n");
  return 0;
}

