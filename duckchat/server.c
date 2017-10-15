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
static void print_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(-1);
}


/**
 * FIXME
 */
int main(int argc, char *argv[]) {

    char buffer[BUFF_SIZE];

    if (argc != 3) {
	sprintf(buffer, "Usage: %s domain_name port_num", argv[0]);
	print_error(buffer);
    }

    return 0;
}
