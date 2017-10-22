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
#include <signal.h>
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


/**
 * 
 */
typedef struct user {
    LinkedList *channels;
    char *ip_addr;
    char *username;
    int is_alive;
} User;

/**
 * FIXME
 */
static User *malloc_user(const char *ip, const char *name) {
    
    User *new_user;
    if ((new_user = (User *)malloc(sizeof(User))) != NULL) {

	new_user->channels = ll_create();
	new_user->ip_addr = (char *)malloc(strlen(ip) + 1);
	new_user->username = (char *)malloc(strlen(name) + 1);
	if (new_user->channels == NULL || new_user->ip_addr == NULL ||
	    new_user->username == NULL) {
	    if (new_user->channels != NULL) ll_destroy(new_user->channels, free);
	    if (new_user->ip_addr != NULL) free(new_user->ip_addr);
	    if (new_user->username != NULL) free(new_user->username);
	    free(new_user);
	    return NULL;
	}

	strcpy(new_user->ip_addr, ip);
	strncpy(new_user->username, name, (USERNAME_MAX - 1));
	new_user->is_alive = 1;
    }
    return new_user;
}

/**
 * FIXME
 */
static void free_user(User *user) {
    if (user != NULL) {
	ll_destroy(user->channels, free);
	free(user->ip_addr);
	free(user->username);
	free(user);
    }
}

/**
 * FIXME
 */
static void server_send_error(struct sockaddr_in *client_addr, const char *msg) {
    
    struct text_error error_packet;
    error_packet.txt_type = TXT_ERROR;
    strncpy(error_packet.txt_error, msg, (SAY_MAX - 1));
    sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)client_addr, sizeof(client_addr));
}

/**
 * FIXME
 */
static void server_login_request(const char *packet, char *client_ip,
				struct sockaddr_in *client_addr) {

    User *new_user;
    struct request_login *login_packet = (struct request_login *) packet;

    if ((new_user = malloc_user(client_ip, login_packet->req_username)) == NULL) {
	server_send_error(client_addr, "Error: Failed to log into the server.");
	return;
    }
    if (!hm_put(users, client_ip, new_user, NULL)) {
	server_send_error(client_addr, "Error: Failed to log into the server.");
	free_user(new_user);
	return;
    }

    fprintf(stdout, "User %s logged in from %s\n", new_user->username,
		new_user->ip_addr);
}

/**
 * FIXME
 */
static void server_join_request(UNUSED const char *packet) {
    puts("JOIN packet received.");
}

/**
 * FIXME
 */
static void server_leave_request(UNUSED const char *packet) {
    puts("LEAVE packet received.");
}

/**
 * FIXME
 */
static void server_say_request(UNUSED const char *packet) {
    puts("SAY packet received.");
}

/**
 * FIXME
 */
static void server_list_request(UNUSED const char *packet) {
    puts("LIST packet received.");
}

/**
 * FIXME
 */
static void server_who_request(UNUSED const char *packet) {
    puts("WHO packet received.");
}

/**
 * FIXME
 */
static void server_logout_request(char *client_ip) {
    
    User *user;

    (void)hm_remove(users, client_ip, (void **)&user);
    char *username = ((user != NULL) ? user->username : "<UNKNOWN>");
    if (user != NULL) free(user);
    /// FIXME-Remove user from all channels

    fprintf(stdout, "User %s logged out\n", username);
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
 * FIXME
 */
static void free_ll(LinkedList *ll) {
    if (ll != NULL)
	ll_destroy(ll, (void *)free_user);
}

/**
 * FIXME
 */
static void sig_handler(UNUSED int signo) {
    fprintf(stdout, "\n\nShutting down server...\n");
    if (socket_fd != -1)
	close(socket_fd);
    if (users != NULL)
	hm_destroy(users, (void *)free_user);
    if (channels != NULL)
	hm_destroy(channels, (void *)free_ll);
    exit(0);
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

    /* FIXME */
    if (signal(SIGINT, sig_handler))
	print_error("Failed to catch SIGINT.");

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
		server_logout_request(client_ip);
		break;
	    case REQ_JOIN:
		server_join_request(buffer);
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
