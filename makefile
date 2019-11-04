export LD_RUN_PATH := /home/reseda/security/libsodium-stable/lib
PFLAGS = -Wall -I/home/reseda/security/libsodium-stable/include \
-L/home/reseda/security/libsodium-stable/lib -lreadline -lsodium

driver : driver.c principal-functions.o trusted-functions.o
	gcc -o $(PFLAGS) driver.c principal-functions.o trusted-functions.o

principal-functions.o : principal-functions.c
	gcc -c $(PFLAGS) principal-functions.c
trusted-functions.o : trusted-functions.c
	gcc -c $(PFLAGS) trusted-functions.c
clean :
	rm file-encryption driver.o trusted-functions.o principal-functions.o
