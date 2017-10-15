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

#define BUFF_SIZE 256

#define UNUSED __attribute__((unused))

static char username[USERNAME_MAX];
static char active_channel[CHANNEL_MAX];
static int socket_fd;

//////////////////////////////////
//// FIXME = ERROR CHECK sendto()

static void client_join(struct sockaddr_in server, const char *request) {
    struct request_join join_packet;
    join_packet.req_type = REQ_JOIN;
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    strncpy(join_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_leave(struct sockaddr_in server, const char *request) {
    struct request_leave leave_packet;
    leave_packet.req_type = REQ_LEAVE;
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    strncpy(leave_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &leave_packet, sizeof(leave_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_say(struct sockaddr_in server, const char *request) {
    struct request_say say_packet;
    say_packet.req_type = REQ_SAY;
    strncpy(say_packet.req_channel, active_channel, (CHANNEL_MAX - 1));
    strncpy(say_packet.req_text, request, (SAY_MAX - 1));
    sendto(socket_fd, &say_packet, sizeof(say_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_list(struct sockaddr_in server) {
    struct request_list list_packet;
    list_packet.req_type = REQ_LIST;
    sendto(socket_fd, &list_packet, sizeof(list_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_who(struct sockaddr_in server, const char *request) {
    struct request_who who_packet;
    who_packet.req_type = REQ_WHO;
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    strncpy(who_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &who_packet, sizeof(who_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

static void client_switch(const char *request) {
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    memset(active_channel, 0, sizeof(active_channel));
    strncpy(active_channel, ++channel, (CHANNEL_MAX - 1));
    puts(active_channel);
}

static void client_logout(struct sockaddr_in server) {
    struct request_logout logout_packet;
    logout_packet.req_type = REQ_LOGOUT;
    sendto(socket_fd, &logout_packet, sizeof(logout_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * FIXME
 */
static void client_help(void) {
    fprintf(stdout, "Possible commands are:\n");
    fprintf(stdout, "   /exit: Logout and exit the client software.\n");
    fprintf(stdout, "   /join <channel>: Join the named channel, creating it if it does not exist.\n");
    fprintf(stdout, "   /leave <channel>: Leave the named channel.\n");
    fprintf(stdout, "   /list: Lists the names of all the available channels.\n");
    fprintf(stdout, "   /who <channel>: Lists all users who are on the named channel.\n");
    fprintf(stdout, "   /switch <channel>: Switch to the named channel you already joined.\n");
    fprintf(stdout, "   /help: Lists all available commands.\n");
}

/**
 * FIXME
 */
static void cleanup(void) {
    close(socket_fd);
    cooked_mode();
}

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
    struct hostent *host_end;
    struct request_login login_packet;
    int port_num, i;
    char ch;
    char buffer[BUFF_SIZE];

    /* Assert that the number of arguments given is correct; print usage otherwise */
    if (argc != 4) {
	sprintf(buffer, "Usage: %s server_socket server_port username", argv[0]);
	print_error(buffer);
    }

    if ((atexit(cleanup)) != 0)
	print_error("Error - Call to atexit() failed.");

    if (strlen(argv[1]) > UNIX_PATH_MAX) {
	sprintf(buffer, "Error - Path name to domain socket exceeds the length allowed (%d)",
		    UNIX_PATH_MAX);
	print_error(buffer);
    }

    if ((host_end = gethostbyname(argv[1])) == NULL)
	print_error("Error - Failed to locate the host.");
    port_num = atoi(argv[2]);

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)host_end->h_addr, (char *)&server_addr.sin_addr.s_addr, host_end->h_length);
    server_addr.sin_port = htons(port_num);

    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Error - Failed to open a socket for client.");

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	print_error("Error - Failed to connect client to server.");

    strncpy(username, argv[3], (USERNAME_MAX - 1));
    if (strlen(argv[3]) > USERNAME_MAX) {
	fprintf(stdout, "Username length exceeds the length allowed (%d)\n", USERNAME_MAX);
	fprintf(stdout, "Your username will be: %s\n", username);
    }

    strncpy(active_channel, "Common", CHANNEL_MAX);

    login_packet.req_type = REQ_LOGIN;
    strncpy(login_packet.req_username, username, USERNAME_MAX);
    sendto(socket_fd, &login_packet, sizeof(login_packet), 0,
		(struct sockaddr *)&server_addr, sizeof(server_addr));

    if (raw_mode() < 0)
	print_error("Error - Failed to switch the terminal to raw mode.");

    while (1) {

	i = 0;
	fprintf(stdout, ">");
	while ((ch = getchar()) != '\n') {
	////// FIXME = ADD DELETEING !!
	    buffer[i++] = ch;
	    putchar(ch);
	}
	
	buffer[i] = '\0';
	fprintf(stdout, "\n");
	if (buffer[0] == '/') {
	    if (strncmp(buffer, "/join", 5) == 0) {
		client_join(server_addr, buffer);
	    } else if (strncmp(buffer, "/leave", 6) == 0) {
		client_leave(server_addr, buffer);
	    } else if (strncmp(buffer, "/list", 5) == 0) {
		client_list(server_addr);
	    } else if (strncmp(buffer, "/who", 4) == 0) {
		client_who(server_addr, buffer);
	    } else if (strncmp(buffer, "/switch", 7) == 0) {
		client_switch(buffer);
	    } else if (strncmp(buffer, "/exit", 5) == 0) {
		client_logout(server_addr);
		break;
	    } else if (strncmp(buffer, "/help", 5) == 0) {
		client_help();
	    } else {
		fprintf(stdout, "*Unknown command\n");
	    }
	} else {
	    client_say(server_addr, buffer);
	}
    }

    return 0;
}
