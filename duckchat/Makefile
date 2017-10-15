CC=gcc
CFLAGS=-Wall -W -g

FILES=Makefile client.c server.c
OBJECTS=client.o server.o raw.o
EXECS=client server


all: $(EXECS)

client: client.o
	$(CC) $(CFLAGS) client.o -o client

server: server.o
	$(CC) $(CFLAGS) server.o -o server

tarfile:
	mkdir duckchat/
	cp $(FILES) duckchat/
	tar -zcvf duckchat.tgz duckchat/
	tar -ztvf duckchat.tgz
	rm -fr duckchat/

help:
	@echo "Possible targets for make:"
	@echo "    all     - Compiles both client & server executables."
	@echo "    client  - Compiles the client executable."
	@echo "    server  - Compiles the server executable."
	@echo "    tarfile - Creates a tar archive of the project."
	@echo "    help    - Display list of possible make targets."
	@echo "    clean   - Removes project executables and object files."

clean:
	rm -f $(OBJECTS) $(EXECS)

client.o: client.c duckchat.h
server.o: server.c duckchat.h

