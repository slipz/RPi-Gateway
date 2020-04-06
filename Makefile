gcc -Wall main.c security_extension.c -o a.out -lssl -lcrypto

CC = gcc
CFLAGS = -Wall

sec: main.c security_extension.c
	$(CC) $(CFLAGS) -o a.out main.c security_extension.c -lssl -lcrypto