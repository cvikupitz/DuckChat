/**
 * client.c
 * Author: Cole Vikupitz
 *
 * FIXME - DESCRIPTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "duckchat.h"
#include "raw.h"

#define BUFF_SIZE 4096
#define UNUSED __attribute__((unused))

/**
 * FIXME
 */
static void print_and_exit(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(-1);
}


/**
 * FIXME
 */
int main(int argc, char *argv[]) {

    struct sockaddr_in server_addr;
    struct hostent *host;
    int client_fd;
    char buffer[BUFF_SIZE];
    const char *username;

    /* Assert that the correct number of arguments were given */
    if (argc != 4) {
	sprintf(buffer, "Usage: %s server_socket server_port username", argv[0]);
	print_and_exit(buffer);
    }

    if ((client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_and_exit("Error: Failed to create the socket.");

    server_addr.sin_family = AF_INET;
    if ((host = gethostbyname(argv[1])) == 0)
	print_and_exit("Error: Unknown host.");///////FIXME, should not be an error

    bcopy((char *)host->h_addr, (char *)&server_addr.sin_addr, host->h_length);
    server_addr.sin_port = htons(atoi(argv[2]));

    strcpy(buffer, "This is a test.");
    send(client_fd, buffer, BUFF_SIZE, 0);

    username = argv[3];
    fprintf(stdout, "Welcome %s\n", username);

    return 0;
}
