/**
 * server.c
 * Author: Cole Vikupitz
 *
 * FIXME - DESCRIPTION
 */

#include <stdio.h>
#include <stdlib.h>
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

    char buffer[BUFF_SIZE];

    /* Assert that the correct number of arguments were given */
    if (argc != 3) {
	sprintf(buffer, "Usage: %s domain_name port_num", argv[0]);
	print_and_exit(buffer);
    }

    

    return 0;
}
