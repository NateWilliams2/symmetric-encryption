//returns true if a given message of length msg_len is full of null-chars. returns false otherwise
int msg_is_null(unsigned char* msg, size_t msg_len);

//copies principal names from message into p1 and p2
int read_names_from_msg(unsigned char* message, unsigned char* p1, unsigned char* p2);

//encrypts a given message with a given session key, saves that message with a nonce in message_enc
int encrypt_and_send_message(unsigned char* session_key, unsigned char* message, size_t msg_size, unsigned char* message_enc);

//Verifies a session key message. Checks for null msg, decryption, name extraction, name matching, timestamp parsing, timestamp matching. Then writes decrypted session_key
int verify_session_key_message(unsigned char* p1msg, unsigned char* p2msg, unsigned char* p1, size_t p1_size, unsigned char* p2, size_t p2_size, unsigned char* trusted, unsigned char* session_key);

//receives and decrypts a message. Checks for null msg, decryption, name extraction, name matching, timestamp parsing, timestamp matching. Extracts session key from key_message_enc and uses that key to decrypt ciphertext. writes decrypted message to message_dec. 
int receive_and_decrypt_message(unsigned char* key_message_enc, unsigned char* ciphertext, unsigned char* message_dec, unsigned char* p1, size_t p1_size, unsigned char* p2, size_t p2_size,unsigned char* trusted, size_t t_size);

//generates a session key request in request array: name of principal 1 + % + name of principal 2 + %
int session_key_request(unsigned char *principal_1, size_t p1_size, unsigned char *principal_2, size_t p2_size, unsigned char *request);

//generates a trusted key between a principal and a trusted third party, and stores that key in both the principal and trusted party directories
int generate_trusted_key(unsigned char *principal, unsigned char *trusted);


