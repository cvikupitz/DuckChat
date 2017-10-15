/**
 * server.c
 * Author: Cole Vikupitz
 *
 * FIXME - DESCRIPTION
 */

#include <stdio.h>
#include <stdlib.h>
#include "duckchat.h"

#define BUFF_SIZE 4096
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

    //// FIXME connect server here...

    while (1) {
	/// FIXME server work here...
    }

    return 0;
}
