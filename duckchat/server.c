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

/* Suppress compiler warnings for unused parameters */
#define UNUSED __attribute__((unused))
/* Maximum buffer size for messages and packets */
#define BUFF_SIZE 10000
/* Maximum number of channels allowed on the server at a time */
#define MAX_CHANNELS 50
/* FIXME */
#define DEFAULT_CHANNEL "Common"
/* Refresh rate (in minutes) of the server to forcefully logout inactive users */
#define REFRESH_RATE 2


static struct sockaddr_in server;
static int socket_fd = -1;
static HashMap *users = NULL;
//static HashMap *channels = NULL;


/**
 * FIXME
 */
typedef struct user {
    LinkedList *channels;
    struct sockaddr_in addr;
    socklen_t len;
    char *ip_addr;
    char *username;
    int is_alive;
} User;

/**
 * FIXME
 */
static User *malloc_user(const char *ip, const char *name, struct sockaddr_in *addr, socklen_t len) {

    User *new_user;
    if ((new_user = (User *)malloc(sizeof(User))) != NULL) {
	new_user->channels = ll_create();
	new_user->ip_addr = (char *)malloc(strlen(ip) + 1);
	int name_len = ((strlen(name) > (USERNAME_MAX - 1)) ? (USERNAME_MAX - 1) : strlen(name));
	new_user->username = (char *)malloc(name_len + 1);

	if (new_user->channels == NULL ||
	    new_user->ip_addr == NULL ||
	    new_user->username == NULL) {
	    if (new_user->channels != NULL) ll_destroy(new_user->channels, free);
	    if (new_user->ip_addr != NULL) free(new_user->ip_addr);
	    if (new_user->username != NULL) free(new_user->username);
	    return NULL;
	}

	strcpy(new_user->ip_addr, ip);
	memcpy(new_user->username, name, name_len);
	new_user->username[name_len] = '\0';
	memcpy(&new_user->addr, addr, len);
	new_user->len = len;
    }

    return new_user;    
}

/**
 * FIXME
 */
static void free_user(User *user) {
    
    if (user != NULL) {
	ll_destroy(user->channels, free);
	user->channels = NULL;
	free(user->ip_addr);
	user->ip_addr = NULL;
	free(user->username);
	user->username = NULL;
	free(user);
	user = NULL;
	memset(&user->addr, 0, user->len);
    }
}

/**
 * FIXME
 */
UNUSED static int user_logged_in(char *ip) {
    
    User *user;
    return hm_get(users, ip, (void **)&user);
}

/**
 * FIXME
 */
UNUSED static void remove_user_from_channel(UNUSED char *ip, UNUSED LinkedList *channel) {}

/**
 * FIXME
 */
static void server_send_error(struct sockaddr_in addr, socklen_t len, const char *msg) {
    
    struct text_error error_packet;
    memset(&error_packet, 0, sizeof(error_packet));
    error_packet.txt_type = TXT_ERROR;
    strncpy(error_packet.txt_error, msg, (SAY_MAX - 1));
    sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)&addr, len);
    /*sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)user->addr, user->len);*/
}

/**
 * FIXME
 */
static void server_login_request(const char *packet, char *client_ip, struct sockaddr_in *addr, socklen_t len) {

    User *user;
    struct request_login *login_packet = (struct request_login *) packet;
    if ((user = malloc_user(client_ip, login_packet->req_username, addr, len)) == NULL) {
	server_send_error(*addr, len, "Error: Failed to log into the server.");
	return;
    }
    if (!hm_put(users, client_ip, user, NULL)) {
	server_send_error(*addr, len, "Error: Failed to log into the server.");
	free(user);
	return;
    }

    server_send_error(user->addr, user->len, "Logged in!!!");
    puts("LOGIN packet received.");
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
static void server_list_request(UNUSED char *client_ip) {
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
static void server_logout_request(UNUSED char *client_ip) {
    puts("LOGOUT packet received.");
}

/**
 * FIXME
 */
static void cleanup(void) {
    
    if (socket_fd != -1)
	close(socket_fd);
    if (users != NULL)
	hm_destroy(users, (void *)free_user);
}

/**
 * Prints the specified message to standard error stream as a program error
 * message, then terminates the server application.
 */
static void print_error(const char *msg) {
    
    fprintf(stderr, "Server: %s\n", msg);
    exit(0);
}

/**
 * FIXME
 */
static void sig_handler(UNUSED int signo) {
    
    fprintf(stdout, "\n\nShutting down server...\n");
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

    /* Register function to cleanup when user stops the server */
    /* Also register the cleanup() function to be invoked upon program termination */
    if (signal(SIGINT, sig_handler))
	print_error("Failed to catch SIGINT.");
    if ((atexit(cleanup)) != 0)
	print_error("Call to atexit() failed.");

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

    /* Obtain the address of the specified host */
    if ((host_end = gethostbyname(argv[1])) == NULL)
	print_error("Failed to locate the host.");

    /* Create server address struct, set internet family, address, & port number */
    memset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    memcpy((char *)host_end->h_addr, (char *)&server.sin_addr.s_addr, host_end->h_length);
    server.sin_port = htons(port_num);

    /* Create the UDP socket, bind name to socket */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to create a socket for the server.");
    if (bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
	print_error("Failed to assign the requested address.");

    /* Create & initialize ADTs for server to use */
    if ((users = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");

    /* Display successful launch title, timestamp & address */
    time(&timer);
    fprintf(stdout, "***** Launched DuckChat server ~ %s", ctime(&timer)); 
    fprintf(stdout, "***** Server assigned to address %s:%d\n", inet_ntoa(server.sin_addr),
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
		server_login_request(buffer, client_ip, &client, addr_len);
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
		server_list_request(client_ip);
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
