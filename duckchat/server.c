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
/// FIXME - server mesage when error occurs

/* Suppress compiler warnings for unused parameters */
#define UNUSED __attribute__((unused))
/* Maximum buffer size for messages and packets */
#define BUFF_SIZE 10000
/* FIXME */
#define MAX_CHANNELS 100
/*  */
#define MAX_CHANNEL_USERS 250
/*  */
#define DEFAULT_CHANNEL "Common"
/* Refresh rate (in minutes) of the server to forcefully logout inactive users */
#define REFRESH_RATE 2

/**/
static struct sockaddr_in server;
/**/
static int socket_fd = -1;
/**/
static HashMap *users = NULL;
/**/
static HashMap *channels = NULL;


/**
 * FIXME
 */
typedef struct user {
    struct sockaddr_in *addr;
    socklen_t len;
    LinkedList *channels;   /* List of channels */
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
	new_user->addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	new_user->channels = ll_create();
	new_user->ip_addr = (char *)malloc(strlen(ip) + 1);
	int name_len = ((strlen(name) > (USERNAME_MAX - 1)) ? (USERNAME_MAX - 1) : strlen(name));
	new_user->username = (char *)malloc(name_len + 1);

	if (new_user->addr == NULL || new_user->channels == NULL || 
	    new_user->ip_addr == NULL || new_user->username == NULL) {
	    if (new_user->addr != NULL) free(new_user->addr);
	    if (new_user->channels != NULL) ll_destroy(new_user->channels, free);
	    if (new_user->ip_addr != NULL) free(new_user->ip_addr);
	    if (new_user->username != NULL) free(new_user->username);
	    return NULL;
	}

	*new_user->addr = *addr;
	new_user->len = len;
	strcpy(new_user->ip_addr, ip);
	memcpy(new_user->username, name, name_len);
	new_user->username[name_len] = '\0';
    }

    return new_user;    
}

/**
 * FIXME
 */
static void free_user(User *user) {
    
    if (user != NULL) {
	free(user->addr);
	ll_destroy(user->channels, free);
	free(user->ip_addr);
	free(user->username);
	free(user);
    }
}

/**
 * FIXME
 */
static void print_timestamp(void) {

    struct tm *timestamp;
    time_t timer;
    time(&timer);
    timestamp = localtime(&timer);
    fprintf(stdout, "[%02d/%02d/%d %02d:%02d] ", (timestamp->tm_mon + 1), timestamp->tm_mday,
		(1900 + timestamp->tm_year), timestamp->tm_hour, timestamp->tm_min);
}

/**
 * FIXME
 */
UNUSED static void logout_user(UNUSED User *user) {

}

/**
 * FIXME
 */
static void server_send_error(struct sockaddr_in *addr, socklen_t len, const char *msg) {
    
    struct text_error error_packet;
    memset(&error_packet, 0, sizeof(error_packet));
    error_packet.txt_type = TXT_ERROR;
    strncpy(error_packet.txt_error, msg, (SAY_MAX - 1));
    sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)addr, len);
}

/**
 * FIXME
 */
static void server_login_request(const char *packet, char *client_ip, struct sockaddr_in *addr, socklen_t len) {

    User *user;
    struct request_login *login_packet = (struct request_login *) packet;
    if ((user = malloc_user(client_ip, login_packet->req_username, addr, len)) == NULL) {
	server_send_error(addr, len, "Failed to log into the server.");
	return;
    }
    if (!hm_put(users, client_ip, user, NULL)) {
	server_send_error(addr, len, "Failed to log into the server.");
	free(user);
	return;
    }

    fprintf(stdout, "User %s logged in from %s\n", user->username, user->ip_addr);
}

/**
 * FIXME
 */
static void server_join_request(const char *packet, char *client_ip, struct sockaddr_in *addr, socklen_t len) {
    
    User *user;
    LinkedList *user_list;
    char buffer[SAY_MAX], *joined;
    struct request_join *join_packet = (struct request_join *) packet;

    if (!hm_get(users, client_ip, (void **)&user)) {
	server_send_error(addr, len, "You are not currently logged in.");
	return;
    }

    int ch_len = ((strlen(join_packet->req_channel) > (CHANNEL_MAX - 1)) ?
				(CHANNEL_MAX - 1) : strlen(join_packet->req_channel));
    if ((joined = (char *)malloc(ch_len + 1)) == NULL) {
	sprintf(buffer, "Failed to join the channel %s.", join_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	return;
    }

    memcpy(joined, join_packet->req_channel, ch_len);
    joined[ch_len] = '\0';
    if (!ll_add(user->channels, joined)) {
	sprintf(buffer, "Failed to join the channel %s.", joined);
	server_send_error(user->addr, user->len, buffer);
	free(joined);
	return;
    }

    if (!hm_get(channels, joined, (void **)&user_list)) {
	if ((user_list = ll_create()) == NULL) {
	    sprintf(buffer, "Failed to join the channel %s.", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
	if (!ll_add(user_list, user)) {
	    ll_destroy(user_list, NULL);
	    sprintf(buffer, "Failed to join the channel %s.", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
	if (!hm_put(channels, joined, user_list, NULL)) {
	    ll_destroy(user_list, NULL);
	    sprintf(buffer, "Failed to join the channel %s.", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
	fprintf(stdout, "User %s created the channel %s\n", user->username, joined);
	print_timestamp();

    } else {
	if (!ll_add(user_list, user)) {
	    sprintf(buffer, "Failed to join the channel %s.", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
    }

    fprintf(stdout, "User %s joined the channel %s\n", user->username, joined);
}

/**
 * FIXME
 */
static void server_leave_request(const char *packet, char *client_ip, struct sockaddr_in *addr, socklen_t len) {

    User *user, *temp;
    LinkedList *user_list;
    char *ch, channel[CHANNEL_MAX], buffer[SAY_MAX];
    int removed = 0;
    long i;
    struct request_leave *leave_packet = (struct request_leave *) packet;

    if (!hm_get(users, client_ip, (void **)&user)) {
	server_send_error(addr, len, "You are not currently logged in.");
	return;
    }

    memset(channel, 0, sizeof(channel));
    strncpy(channel, leave_packet->req_channel, (CHANNEL_MAX - 1));
    if (!hm_get(channels, channel, (void **)&user_list)) {
	sprintf(buffer, "No channel by the name %s", leave_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	return;
    }

    for (i = 0L; i < ll_size(user->channels); i++) {
	(void)ll_get(user->channels, i, (void **)&ch);
	if (strcmp(channel, ch) == 0) {
	    ll_remove(user->channels, i, (void **)&ch);
	    free(ch);
	    removed = 1;
	    break;
	}
    }

    for (i = 0L; i < ll_size(user_list); i++) {
	(void)ll_get(user_list, i, (void **)&temp);
	if (strcmp(user->ip_addr, temp->ip_addr) == 0) {
	    ll_remove(user_list, i, (void **)&temp);
	    break;
	}
    }

    if (removed)
	fprintf(stdout, "User %s left the channel %s\n", user->username, channel);
    else
	fprintf(stdout, "User %s tried to leave non-subscribed/non-existent channel %s\n",
		    user->username, channel);

    if (ll_isEmpty(user_list) && strcmp(channel, DEFAULT_CHANNEL)) {
	hm_remove(channels, client_ip, (void **)&user_list);
	ll_destroy(user_list, NULL);
	print_timestamp();
	fprintf(stdout, "Removed the empty channel %s\n", channel);
    }
}

/**
 * FIXME
 */
static void server_say_request(UNUSED const char *packet) {
    puts("****** SAY packet received.");
}

/**
 * FIXME
 */
static void server_list_request(UNUSED char *client_ip) {
    puts("****** LIST packet received.");
}

/**
 * FIXME
 */
static void server_who_request(UNUSED const char *packet) {
    puts("****** WHO packet received.");
}

/**
 * FIXME
 */
static void server_logout_request(UNUSED char *client_ip) {
    puts("****** LOGOUT packet received.");
}

/**
 * FIXME
 */
static void free_ll(LinkedList *ll) {
    if (ll != NULL)
	ll_destroy(ll, NULL);
}

/**
 * FIXME
 */
static void cleanup(void) {
    
    if (socket_fd != -1)
	close(socket_fd);
    if (channels != NULL)
	hm_destroy(channels, (void *)free_ll);
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
    if ((channels = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    LinkedList *default_ll;
    if ((default_ll = ll_create()) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    if (!hm_put(channels, DEFAULT_CHANNEL, default_ll, NULL))
	print_error("Failed to allocate a sufficient amount of memory.");

    /* Display successful launch title, timestamp & address */
    time_t timer;
    time(&timer);
    fprintf(stdout, "------ Launched DuckChat server ~ %s", ctime(&timer)); 
    fprintf(stdout, "------ Server assigned to address %s:%d\n", inet_ntoa(server.sin_addr),
	    ntohs(server.sin_port));

    /**
     * FIXME
     */
    while (1) {
    
	memset(buffer, 0, sizeof(buffer));
	recvfrom(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &addr_len);
	sprintf(client_ip, "%s:%d", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
	print_timestamp();
	
	struct text *packet_type = (struct text *) buffer;
	switch (packet_type->txt_type) {
	    case REQ_LOGIN:	/**/
		server_login_request(buffer, client_ip, &client, addr_len);
		break;
	    case REQ_LOGOUT:	/**/
		server_logout_request(client_ip);
		break;
	    case REQ_JOIN:  /**/
		server_join_request(buffer, client_ip, &client, addr_len);
		break;
	    case REQ_LEAVE: /**/
		server_leave_request(buffer, client_ip, &client, addr_len);
		break;
	    case REQ_SAY:   /**/
		server_say_request(buffer);
		break;
	    case REQ_LIST:  /**/
		server_list_request(client_ip);
		break;
	    case REQ_WHO:   /**/
		server_who_request(buffer);
		break;
	    default:	/* Do nothing, likey a bogus packet */
		break;
	}
    }

    return 0;
}
