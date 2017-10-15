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

#define BUFF_SIZE 2048
#define UNUSED __attribute__((unused))

static char *username;
static int socket_fd;

//////////////////////////////////
//// FIXME = ERROR CHECK sendto()

static void client_join(struct sockaddr_in server, const char *query) {
    struct request_join join_packet;
    join_packet.req_type = REQ_JOIN;
    char *channel = strchr(query, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    strncpy(join_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_leave(struct sockaddr_in server, const char *query) {
    struct request_leave leave_packet;
    leave_packet.req_type = REQ_LEAVE;
    char *channel = strchr(query, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    strncpy(leave_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &leave_packet, sizeof(leave_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

UNUSED static void client_say(UNUSED struct sockaddr_in server) {
    puts("-- Reached client say...");
}

static void client_list(struct sockaddr_in server) {
    struct request_list list_packet;
    list_packet.req_type = REQ_LIST;
    sendto(socket_fd, &list_packet, sizeof(list_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_who(struct sockaddr_in server, const char *query) {
    struct request_who who_packet;
    who_packet.req_type = REQ_WHO;
    char *channel = strchr(query, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    strncpy(who_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &who_packet, sizeof(who_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_logout(struct sockaddr_in server) {
    struct request_logout logout_packet;
    logout_packet.req_type = REQ_LOGOUT;
    sendto(socket_fd, &logout_packet, sizeof(logout_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void print_error(const char *msg) {
    perror(msg);///FIXME-fprintf()
    exit(-1);
}

int main(int argc, char *argv[]) {

    struct sockaddr_in server_addr;
    struct hostent *host_end;
    struct request_login login_packet;
    int port_num;
    char buffer[BUFF_SIZE];

    /* Assert that the number of arguments given is correct; print usage otherwise */
    if (argc != 4) {
	fprintf(stderr, "Usage: %s server_socket server_port username\n", argv[0]);
	exit(-1);
    }

    if ((host_end = gethostbyname(argv[1])) == NULL)
	print_error("Error - Failed to locate the host.\n");
    port_num = atoi(argv[2]);

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)host_end->h_addr, (char *)&server_addr.sin_addr.s_addr, host_end->h_length);
    server_addr.sin_port = htons(port_num);

    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Error - Failed to open a socket for client.\n");

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	print_error("Error - Failed to connect client to server.\n");

    if ((username = (char *)malloc(USERNAME_MAX + 1)) == NULL)
	perror("Error - Unable to allocate a sufficient amount of memory.\n");
    strncpy(username, argv[3], USERNAME_MAX);
    if (strlen(argv[3]) > USERNAME_MAX) {
	fprintf(stdout, "Username length exceeds the limit allowed (%d characters)\n", USERNAME_MAX);
	fprintf(stdout, "Your username will be: %s\n", username);
    }

    login_packet.req_type = REQ_LOGIN;
    strncpy(login_packet.req_username, username, USERNAME_MAX);
    sendto(socket_fd, &login_packet, sizeof(login_packet), 0,
		(struct sockaddr *)&server_addr, sizeof(server_addr));

    while (1) {

	fputs(">", stdout);
	fgets(buffer, sizeof(buffer), stdin);
	buffer[strlen(buffer) - 1] = '\0';


	if (buffer[0] == '/') {
	    if (strncmp(buffer, "/join", 5) == 0) {
		client_join(server_addr, buffer);
	    } else if (strncmp(buffer, "/leave", 6) == 0) {
		client_leave(server_addr, buffer);
	    } else if (strncmp(buffer, "/list", 5) == 0) {
		client_list(server_addr);
	    } else if (strncmp(buffer, "/who", 4) == 0) {
		client_who(server_addr, buffer);
	    } else if (strncmp(buffer, "/exit", 5) == 0) {
		client_logout(server_addr);
		break;
	    } else {
		fprintf(stdout, "*Unknown command\n");
	    }
	} else {
	    client_say(server_addr);
	}
    }

    close(socket_fd);
    return 0;
}
