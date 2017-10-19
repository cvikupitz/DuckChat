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
#include "duckchat.h"

/* Buffer size for messages and packets */
#define BUFF_SIZE 1024
/* FIXME */
#define REFRESH_RATE 2
#define UNUSED __attribute__((unused))



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

    /* Parse port number given by user, assert that it is in valid range */
    /* Print error message and exit otherwise */
    /* Port numbers typically go up to 65535 (0-1024 for privileged services) */
    port_num = atoi(argv[2]);
    if (port_num < 0 || port_num > 65535)
	print_error("Server socket must be in the range [0, 65535].");

    
    /* FIXME...... */


    return 0;
}
