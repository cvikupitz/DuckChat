/**
 * client.c
 * Author: Cole Vikupitz
 *
 * Client side of a chat application using the DuckChat protocol. The client sends
 * and receives packets from a server using this protocol and handles each of the
 * packets accordingly.
 *
 * Usage: ./client server_socket server_port username
 */

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "duckchat.h"

/// FIXME - USE htons(), hotl().. for byte order....

/* Maximum buffer size for messages and packets */
#define BUFF_SIZE 20000

/* Socket address for the server */
static struct sockaddr_in server;
/* File descriptor for the client's socket */
static int socket_fd = -1;




int main(int argc, char *argv[]) {

    struct hostent *host_end;
    struct request_login login_packet;
    struct request_join join_packet;
    int port_num;

    /* Assert that the correct number of arguments were given */
    /* Print program usage otherwise */
    if (argc != 3) {
	fprintf(stdout, "Usage: %s server_socket server_port\n", argv[0]);
	return 0;
    }

    host_end = gethostbyname(argv[1]);
    port_num = atoi(argv[2]);

    /* Create server address struct, set internet family, address, & port number */
    memset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    memcpy((char *)host_end->h_addr, (char *)&server.sin_addr.s_addr, host_end->h_length);
    server.sin_port = htons(port_num);

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    connect(socket_fd, (struct sockaddr *)&server, sizeof(server));

    /* Send a packet to the server to log user in */
    memset(&login_packet, 0, sizeof(login_packet));
    login_packet.req_type = REQ_LOGIN;
    strncpy(login_packet.req_username, "", USERNAME_MAX);
    sendto(socket_fd, &login_packet, sizeof(login_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
    /* Send a packet to the server to join the default channel */
    memset(&join_packet, 0, sizeof(join_packet));
    join_packet.req_type = REQ_JOIN;
    strncpy(join_packet.req_channel, "Common", (CHANNEL_MAX - 1));
    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		(struct sockaddr *)&server, sizeof(server));


    return 0;
}
