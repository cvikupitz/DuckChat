/**
 * client.c
 * Author: Cole Vikupitz
 *
 * FIXME - DESCRIPTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
static void print_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(-1);
}


/**
 * FIXME
 */
int main(int argc, char *argv[]) {

    struct sockaddr_in server_addr;
    struct hostent *hp;
    int client_fd, port_num;
    char buffer[BUFF_SIZE];
    const char *username;

    if (argc != 4) {
	sprintf(buffer, "Usage: %s server_socket server_port username", argv[0]);
	print_error(buffer);
    }

    username = argv[3];
    port_num = atoi(argv[2]);

    if ((client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Call to socket() failed.");

    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port_num);

    if (bind(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	print_error("Call to bind() failed.");

    close(client_fd);
    return 0;
}
