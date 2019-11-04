Run the following commands in order to compile the program file-encryption:

export LD_RUN_PATH=/home/reseda/security/libsodium-stable/lib


gcc -c -Wall   -I/home/reseda/security/libsodium-stable/include   -L/home/reseda/security/libsodium-stable/lib   -lreadline -lsodium  principal-functions.c trusted-functions.c

gcc -o  file-encryption -Wall   -I/home/reseda/security/libsodium-stable/include   -L/home/reseda/security/libsodium-stable/lib   -lreadline -lsodium driver.c 

