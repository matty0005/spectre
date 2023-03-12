CFLAGS= -pedantic -Wall -std=gnu99
CC=gcc
PROGRAM=main.c
     
all: spectre

spectre: 
	$(CC) $(CFLAGS) main.c -o spectre 


clean: 
	rm -rf spectre