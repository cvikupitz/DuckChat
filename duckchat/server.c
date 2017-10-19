/**
 * server.c
 * Author: Cole Vikupitz
 *
 * FIXME - DESCRIPTION
 */

#include <stdio.h>
#include <stdlib.h>
#include "duckchat.h"

#define BUFF_SIZE 1024
#define UNUSED __attribute__((unused))



/**
 * FIXME
 */
static void cleanup(void) {
    /////
}

/**
 * FIXME
 */
static void print_error(const char *msg) {
    fprintf(stderr, "Server: %s\n", msg);
    exit(-1);
}


/**
 * FIXME
 */
int main(int argc, char *argv[]) {

    struct hostent *host_end;
    struct request_login login_packet;
    fd_set receiver;
    int port_num, i;
    char ch;
    char buffer[BUFF_SIZE];

    if (argc != 3) {
	fprintf(stdout, "Usage: %s domain_name port_num\n", argv[0]);
	return 0;
    }

    if (atexit(cleanup) != 0)
	print_error("Call to atexit() failed.");

    if (strlen(argv[1]) > UNIX_PATH_MAX) {
	sprintf(buffer, "Path name to domain socket length exceeds the length allowed (%d).",
			UNIX_PATH_MAX);
	print_error(buffer);
    }

    /* FIXME */
    if ((host_end = gethostbyname(argv[1])) == NULL)
	print_error("Failed to locate the host.");
    
    /* Parse port number given by user, assert that it is in valid range */
    /* Print error message and exit otherwise */
    /* Port numbers typically go up to 65535 (0-1024 for privileged services) */
    port_num = atoi(argv[2]);
    if (port_num < 0 || port_num > 65535)
	print_error("Server socket must be in the range [0, 65535].");

    /* FIXME */
    bzero((char *)&server, sizeof(server));
    server.sin_family = AF_INET;
    bcopy((char *)host_end->h_addr, (char *)&server.sin_addr.s_addr, host_end->h_length);
    server.sin_port = htons(port_num);

    while (1) {
	/// FIXME server work here...
    }

    return 0;
}
