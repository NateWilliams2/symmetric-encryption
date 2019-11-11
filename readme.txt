Run the following commands in order to compile the program file-encryption:

export LD_RUN_PATH=/home/reseda/security/libsodium-stable/lib



gcc -c -Wall   -I/home/reseda/security/libsodium-stable/include   -L/home/reseda/security/libsodium-stable/lib   -lreadline -lsodium  principal-functions.c trusted-functions.c file-utility.c

gcc -o  file-encryption -Wall   -I/home/reseda/security/libsodium-stable/include   -L/home/reseda/security/libsodium-stable/lib   -lreadline -lsodium driver.c trusted-functions.o principal-functions.o file-utility.o


To run the program, first make sure you are in a directory that includes the folders "alice" "bob" and "sam". They can be empty. then enter the command:
file-encryption
