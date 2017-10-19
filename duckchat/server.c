/**
 * server.c
 * Author: Cole Vikupitz
 *
 * Server side of a chat application using the DuckChat protocol. The server receives
 * and sends packets to and from clients using this protocol and handles each of the
 * packets accordingly.
 *
 * Usage: ./server domain_name port_num
 */

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "duckchat.h"
#include "hashmap.h"

/* Maximum buffer size for messages and packets */
#define BUFF_SIZE 10000
/* FIXME */
#define MAX_CHANNELS 100
/* FIXME */
#define MAX_CHANNEL_USERS 50
/* Refresh rate (in minutes) of the server to forcefully logout inactive users */
#define REFRESH_RATE 2

#define UNUSED __attribute__((unused))


static struct sockaddr_in server;
static int socket_fd = -1;
static HashMap *users = NULL;


/***/
UNUSED static void server_login_user(UNUSED const char *packet) {}

/***/
UNUSED static void server_join_channel(UNUSED const char *packet) {}

/***/
UNUSED static void server_leave_channel(UNUSED const char *packet) {}

/***/
UNUSED static void sever_logout_user(UNUSED const char *packet) {
    
}

/**
 * Prints the specified message to standard error stream as a program error
 * message, then terminates the server application.
 */
static void print_error(const char *msg) {
    fprintf(stderr, "Server: %s\n", msg);
    exit(-1);
}

/**
 * Runs the Duckchat server.
 */
int main(int argc, char *argv[]) {

    struct hostent *host_end;
    int port_num;
    char buffer[BUFF_SIZE];

    /* Assert that the correct number of arguments were given */
    /* Print program usage otherwise */
    if (argc != 3) {
	fprintf(stdout, "Usage: %s domain_name port_num\n", argv[0]);
	return 0;
    }

    /* Assert that path name to unix domain socket does not exceed maximum allowed */
    /* Print error message and exit otherwise */
    /* Maximum length is specified in duckchat.h */
    if (strlen(argv[1]) > UNIX_PATH_MAX) {
	sprintf(buffer, "Path name to domain socket length exceeds the length allowed (%d).",
			UNIX_PATH_MAX);
	print_error(buffer);
    }

    /* FIXME */
    if ((users = hm_create(100L, 0.0f)) == NULL)
	print_error("");

    /* Parse port number given by user, assert that it is in valid range */
    /* Print error message and exit otherwise */
    /* Port numbers typically go up to 65535 (0-1024 for privileged services) */
    port_num = atoi(argv[2]);
    if (port_num < 0 || port_num > 65535)
	print_error("Server socket must be in the range [0, 65535].");

    if ((host_end = gethostbyname(argv[1])) == NULL)
	print_error("Failed to locate the host.");

    bzero((char *)&server, sizeof(server));
    server.sin_family = AF_INET;
    bcopy((char *)host_end->h_addr, (char *)&server.sin_addr.s_addr, host_end->h_length);
    server.sin_port = htons(port_num);

    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to create a socket for the server.");
    if (bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
	print_error("Failed to assign the requested address.");


    /* FIXME...... */

    time_t clock;
    time(&clock);
    fprintf(stdout, "Launched DuckChat server ~ %s", ctime(&clock));

    while (1) {
    
    }

    return 0;
}
