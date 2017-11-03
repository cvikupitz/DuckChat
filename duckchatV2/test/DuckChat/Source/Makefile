CC=g++
#CFLAGS=-Wall -W -g -Werror 
# Uncomment this line for the graduate student version
CFLAGS= -g  -DGRAD=1

LOADLIBES= -lnsl

all: client server

client: client.c raw.c
	$(CC) client.c raw.c $(LOADLIBES) $(CFLAGS) -o client

server: server.c 
	$(CC) server.c $(LOADLIBES) $(CFLAGS) -o server

clean:
	rm -f client server *.o

