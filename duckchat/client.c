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
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "duckchat.h"
#include "raw.h"

#define BUFF_SIZE 256
#define MAX_CHANNELS 20
#define DEFAULT_CHANNEL "Common"
#define UNUSED __attribute__((unused))

static char username[USERNAME_MAX];
static char active_channel[CHANNEL_MAX];
static char subscribed[MAX_CHANNELS][CHANNEL_MAX];
static int socket_fd;

//// FIXME = ERROR CHECK sendto()
//// FIXME - Use bind instead of connect?


/**
 * FIXME
 */
static void client_join_request(struct sockaddr_in server, const char *request) {
    
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    struct request_join join_packet;
    join_packet.req_type = REQ_JOIN;
    strncpy(join_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * FIXME
 */
static void client_leave_request(struct sockaddr_in server, const char *request) {
    
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    struct request_leave leave_packet;
    leave_packet.req_type = REQ_LEAVE;
    strncpy(leave_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &leave_packet, sizeof(leave_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * FIXME
 */
static void client_say_request(struct sockaddr_in server, const char *request) {
    struct request_say say_packet;
    say_packet.req_type = REQ_SAY;
    strncpy(say_packet.req_channel, active_channel, (CHANNEL_MAX - 1));
    strncpy(say_packet.req_text, request, (SAY_MAX - 1));
    sendto(socket_fd, &say_packet, sizeof(say_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * FIXME
 */
static void client_list_request(struct sockaddr_in server) {
    struct request_list list_packet;
    list_packet.req_type = REQ_LIST;
    sendto(socket_fd, &list_packet, sizeof(list_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * FIXME
 */
static void client_who_request(struct sockaddr_in server, const char *request) {
    
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    struct request_who who_packet;
    who_packet.req_type = REQ_WHO;
    strncpy(who_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &who_packet, sizeof(who_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * FIXME
 */
static void client_switch_request(const char *request) {
    int i;
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    ++channel;
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], channel) == 0) {
	    memset(active_channel, 0, sizeof(active_channel));
	    strncpy(active_channel, channel, (CHANNEL_MAX - 1));
	    return;
	}
    }
    fprintf(stdout, "You are not subscribed to the channel %s\n", channel);
}

/**
 * FIXME
 */
static void client_logout_request(struct sockaddr_in server) {
    struct request_logout logout_packet;
    logout_packet.req_type = REQ_LOGOUT;
    sendto(socket_fd, &logout_packet, sizeof(logout_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Prints out full list of all the channels the user is currently subscribed
 * to; invoked when the user enters the special command '/subscribed'.
 */
static void client_subscribed_request(void) {
    int i;
    fprintf(stdout, "Subscribed channels:\n");
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], "") == 0) /* Skip over empty strings */
	    continue;
	fprintf(stdout, "  %s\n", subscribed[i]);
    }
}

/**
 * Prints out full list of possible special commands to user; invoked when
 * the user enters the special command '/help'.
 */
static void client_help_request(void) {
    fprintf(stdout, "Possible commands are:\n");
    fprintf(stdout, "  /join <channel>: Join the named channel, creating it if it doesn't exist.\n");
    fprintf(stdout, "  /leave <channel>: Unsubscribe from the named channel.\n");
    fprintf(stdout, "  /list: Lists the names of all the available channels.\n");
    fprintf(stdout, "  /who <channel>: Lists all users who are on the named channel.\n");
    fprintf(stdout, "  /switch <channel>: Switch to the named channel you are subscribed to.\n");
    fprintf(stdout, "  /subscribed: Lists the names of all the channels you're subscribed to.\n");
    fprintf(stdout, "  /help: Lists all available commands.\n");
    fprintf(stdout, "  /exit: Logout and exit the client software.\n");
}

/**
 * Cleans up after the client software; closes the socket stream the client
 * was using and switches terminal back to cooked mode.
 */
static void cleanup(void) {
    close(socket_fd);
    cooked_mode();
}

/**
 * Prints the specified message to standard error stream as a program error
 * message, then terminates the client application.
 */
static void print_error(const char *msg) {
    fprintf(stderr, "Client Error: %s\n", msg);
    exit(0);
}

/**
 * Runs the client system.
 */
int main(int argc, char *argv[]) {

    struct sockaddr_in server;
    struct hostent *host_end;
    struct request_login login_packet;
    int port_num, i;
    char ch;
    char buffer[BUFF_SIZE];

    /* Assert that the correct number of arguments were given */
    /* Print program usage otherwise */
    if (argc != 4) {
	fprintf(stdout, "Usage: %s server_socket server_port username\n", argv[0]);
	return 0;
    }

    /* Register the cleanup() function to be invoked upon program termination */
    if ((atexit(cleanup)) != 0)
	print_error("Call to atexit() failed.");

    /* Assert that path name to unix domain socket does not exceed maximum allowed */
    /* Print error message and exit otherwise */
    /* Maximum lenght is specified in duckchat.h */
    if (strlen(argv[1]) > UNIX_PATH_MAX) {
	sprintf(buffer, "Path name to domain socket exceeds the length allowed (%d).",
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

    /* FIXME */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to open a socket for client.");
    if (connect(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
	print_error("Failed to connect client to server.");

    /* Initialize username string, do not copy more bytes than maximum allowed */
    /* If the length is too long, notify user, but don't exit */
    /* Max length specified in duckchat.h */
    strncpy(username, argv[3], (USERNAME_MAX - 1));
    if (strlen(argv[3]) > USERNAME_MAX) {
	fprintf(stdout, "* Username length exceeds the length allowed (%d).\n", USERNAME_MAX);
	fprintf(stdout, "* Your username will be: %s\n", username);
    }

    /* FIXME */
    strncpy(active_channel, DEFAULT_CHANNEL, (CHANNEL_MAX - 1));
    strncpy(subscribed[0], DEFAULT_CHANNEL, (CHANNEL_MAX - 1));
    for (i = 1; i < MAX_CHANNELS; i++)
	memset(subscribed[i], 0, sizeof(subscribed[i]));

    /* FIXME */
    login_packet.req_type = REQ_LOGIN;
    strncpy(login_packet.req_username, username, USERNAME_MAX);
    sendto(socket_fd, &login_packet, sizeof(login_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
    /* FIXME */
    sprintf(buffer, "join %s", DEFAULT_CHANNEL);
    client_join_request(server, buffer);

    /* Switch terminal to raw mode, terminate if unable */
    if (raw_mode() < 0)
	print_error("Failed to switch the terminal to raw mode.");

    while (1) {

	i = 0;
	fprintf(stdout, ">");
	while ((ch = getchar()) != '\n') {
	    //// FIXME - DELETE & BACKSPACE
	    if (i != (SAY_MAX - 1)) {
		buffer[i++] = ch;
		putchar(ch);
	    }
	}
	
	buffer[i] = '\0';
	fprintf(stdout, "\n");
	if (buffer[0] == '/') {
	    if (strncmp(buffer, "/join", 5) == 0) {
		client_join_request(server, buffer);
	    } else if (strncmp(buffer, "/leave", 6) == 0) {
		client_leave_request(server, buffer);
	    } else if (strncmp(buffer, "/list", 5) == 0) {
		client_list_request(server);
	    } else if (strncmp(buffer, "/who", 4) == 0) {
		client_who_request(server, buffer);
	    } else if (strncmp(buffer, "/switch", 7) == 0) {
		client_switch_request(buffer);
	    } else if (strncmp(buffer, "/subscribed", 11) == 0) {
		client_subscribed_request();
	    } else if (strncmp(buffer, "/help", 5) == 0) {
		client_help_request();
	    } else if (strncmp(buffer, "/exit", 5) == 0) {
		client_logout_request(server);
		break;
	    } else {
		fprintf(stdout, "*Unknown command\n");
	    }
	} else {
	    client_say_request(server, buffer);
	}
    }

    return 0;
}
