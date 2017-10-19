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
#include "linkedlist.h"

///FIXME - Ensure byte order, htonl/s()....

/* Maximum buffer size for messages and packets */
#define BUFF_SIZE 10000
/* Maximum number of channels allowed on the server at a time */
#define MAX_CHANNELS 50
/* FIXME */
#define DEFAULT_CHANNEL "Common"
/* Refresh rate (in minutes) of the server to forcefully logout inactive users */
#define REFRESH_RATE 2

#define UNUSED __attribute__((unused))


static struct sockaddr_in server;
static int socket_fd = -1;
static HashMap *users = NULL;
static HashMap *channels = NULL;

/*typedef struct user {
    char *ip_addr;
    char *username;
    int is_alive;
} User;*/


/**
 * FIXME
 */
static void server_login_request(const char *packet, char *client_ip,
				struct sockaddr_in *client_addr) {

    char username[USERNAME_MAX];
    struct request_login *login_packet = (struct request_login *) packet;

    strncpy(username, login_packet->req_username, (USERNAME_MAX - 1));
    if (!hm_put(users, client_ip, strdup(username), NULL)) {
	struct text_error error_packet;
	error_packet.txt_type = TXT_ERROR;
	strncpy(error_packet.txt_error, "Error: Failed to log into the server.",
		(SAY_MAX - 1));
	sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)client_addr, sizeof(client_addr));
	return;
    }

    fprintf(stdout, "User %s logged in from %s\n", username, client_ip);
}

/***/
static void server_join_request(UNUSED const char *packet) {
    puts("JOIN packet received.");
}

/***/
static void server_leave_request(UNUSED const char *packet) {
    puts("LEAVE packet received.");
}

/***/
static void server_say_request(UNUSED const char *packet) {
    puts("SAY packet received.");
}

/***/
static void server_list_request(UNUSED const char *packet) {
    
    puts("LIST packet received.");
}

/***/
static void server_who_request(UNUSED const char *packet) {
    puts("WHO packet received.");
}

/***/
static void server_logout_request(UNUSED const char *packet) {
    puts("LOGOUT packet received.");
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

    struct sockaddr_in client;
    struct hostent *host_end;
    struct tm *timestamp;
    time_t timer;
    socklen_t addr_len = sizeof(client);
    int port_num;
    char buffer[BUFF_SIZE], client_ip[128];

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

    /* FIXME */
    if ((host_end = gethostbyname(argv[1])) == NULL)
	print_error("Failed to locate the host.");

    /* FIXME */
    bzero((char *)&server, sizeof(server));
    server.sin_family = AF_INET;
    bcopy((char *)host_end->h_addr, (char *)&server.sin_addr.s_addr, host_end->h_length);
    server.sin_port = htons(port_num);

    /* FIXME */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to create a socket for the server.");
    if (bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
	print_error("Failed to assign the requested address.");

    if ((users = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    if ((channels = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    LinkedList *default_ll;
    if ((default_ll = ll_create()) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    if (!hm_put(channels, DEFAULT_CHANNEL, default_ll, NULL))
	print_error("Failed to allocate a sufficient amount of memory.");

    /* FIXME */
    time(&timer);
    fprintf(stdout, "* Launched DuckChat server ~ %s", ctime(&timer)); 
    fprintf(stdout, "* Server assigned to address %s:%d\n", inet_ntoa(server.sin_addr),
	    ntohs(server.sin_port));

    /**
     * FIXME
     */
    while (1) {
    
	/* FIXME */
	memset(buffer, 0, sizeof(buffer));
	recvfrom(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &addr_len);

	/* Log the timestamp when packet was received */
	time(&timer);
	timestamp = localtime(&timer);
	fprintf(stdout, "[%02d/%02d/%d %02d:%02d] ", (timestamp->tm_mon + 1), timestamp->tm_mday,
		(1900 + timestamp->tm_year), timestamp->tm_hour, timestamp->tm_min);
	sprintf(client_ip, "%s:%d", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
	
	struct text *packet_type = (struct text *) buffer;
	switch (packet_type->txt_type) {
	    case REQ_LOGIN:
		server_login_request(buffer, client_ip, &client);
		break;
	    case REQ_LOGOUT:
		server_logout_request(buffer);
		break;
	    case REQ_JOIN:
		server_join_request(buffer, client_ip);
		break;
	    case REQ_LEAVE:
		server_leave_request(buffer);
		break;
	    case REQ_SAY:
		server_say_request(buffer);
		break;
	    case REQ_LIST:
		server_list_request(buffer);
		break;
	    case REQ_WHO:
		server_who_request(buffer);
		break;
	    default:	/* Do nothing, likey a bogus packet */
		break;
	}
    }

    return 0;
}
