gcc -Wall main.c security_extension.c -o a.out -lssl -lcrypto

CC = gcc
CFLAGS = -Wall

sec: main2.c security_extension.c
	$(CC) $(CFLAGS) -o a.out main2.c security_extension.c -lssl -lcrypto
