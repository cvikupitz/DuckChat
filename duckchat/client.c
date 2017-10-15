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

#define BUFF_SIZE 2048
#define UNUSED __attribute__((unused))

static char username[USERNAME_MAX + 1];
static int socket_fd;


/**
 * FIXME
 */
static void print_error(const char *msg) {
    
    perror(msg);
    exit(-1);
}


/**
 * FIXME
 */
int main(int argc, char *argv[]) {

    struct sockaddr_in server_addr;
    struct hostent *server;
    struct request_login login_packet;
    int port_num;
    char buffer[BUFF_SIZE];

    /* Assert the correct number of arguments were given, print usage otherwise */
    if (argc != 4) {
	fprintf(stderr, "Usage: %s server_socket server_port username\n", argv[0]);
	exit(-1);
    }
    
    if ((server = gethostbyname(argv[1])) == NULL)
	print_error("Error - Failed to locate the server.\n");
    port_num = atoi(argv[2]);

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(port_num);

    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Error - Failed to open a socket for client.\n");

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	perror("Error - Failed to connect client to server.\n");

    strncpy(username, argv[3], USERNAME_MAX);
    if (strlen(argv[3]) > USERNAME_MAX) {
	fprintf(stdout, "Username length exceeds the limit allowed (%d characters)\n", USERNAME_MAX);
	fprintf(stdout, "Your username will be: %s\n", username);
    }

    login_packet.req_type = REQ_LOGIN;
    strncpy(login_packet.req_username, username, USERNAME_MAX);
    send(socket_fd, &login_packet, sizeof(login_packet), 0);

    while (1) {
	fprintf(stdout, ">");
	fgets(buffer, sizeof(buffer), stdin);
    }

    close(socket_fd);
    return 0;
}
