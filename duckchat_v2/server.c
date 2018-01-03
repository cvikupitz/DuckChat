/**
 * server.c
 * Author: Cole Vikupitz
 * Last Modified: 1/2/2018
 *
 * Server side of a chat application using the DuckChat protocol. The server receives
 * and sends packets to and from clients using this protocol and handles each of the
 * packets accordingly.
 *
 * This new version now supports server-to-server communication. Multiple servers can now
 * be run in parallel, reducing individual server load and improving response time(s).
 *
 * Usage: ./server domain_name port_number [domain_name port_number] ...
 *
 * Resources Used:
 * Lots of help about basic socket programming received from Beej's Guide to Socket Programming:
 * https://beej.us/guide/bgnet/output/html/multipage/index.html
 *
 * Help on random number generation with /dev/urandom consulted from:
 * http://www.cs.yale.edu/homes/aspnes/pinewiki/C(2f)Randomization.html
 * 
 * Implementations for the LinkedList and HashMap ADTs that this server uses were borrowed from
 * professor Joe Sventek's ADT library on github (https://github.com/jsventek/ADTs).
 * These implementations are not my own.
 */

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "duckchat.h"
#include "hashmap.h"
#include "linkedlist.h"
#include "properties.h"

/* String for displaying this server's full address */
static char server_addr[128];
/* List of IDs from most recently received packets */
static long id_cache[MSGQ_SIZE];
static int curr_index = 0;
/* File descriptor for the socket to use */
static int socket_fd = -1;
/* HashMap of all users currently logged on */
/* Maps the user's IP address in a string to the user struct */
static HashMap *users = NULL;
/* HashMap of all the channels currently available */
/* Maps the channel name to a linked list of pointers of all users on the channel */
static HashMap *channels = NULL;
/* Hashmap of all the neighboring servers */
/* Maps the server's IP address in a string to the server struct */
static HashMap *neighbors = NULL;
/* HashMap of all channels neighboring servers are subscribed to */
/* Acts as a routing table; maps a list of listening servers to each existing channel */
static HashMap *r_table = NULL;

/**
 * A structure to represent a user logged into the server.
 */
typedef struct {
    struct sockaddr_in *addr;	/* The client's address to send packets to */
    LinkedList *channels;	/* List of channel names user is listening to */
    char *ip_addr;		/* Full IP address of client in string format */
    char *username;		/* The username of user */
    short last_min;		/* Clock minute of last received packet from this client */
} User;

/**
 * A structure to represent a neighboring server.
 */
typedef struct {
    struct sockaddr_in *addr;	/* The address of the neighboring server */
    char *ip_addr;		/* Full IP address of server in string format */
    short last_min;		/* Clock minute of last received S2S request */
} Server;

/**
 * Creates a new instance of a user logged in the server by allocating memory and returns
 * a pointer to the new user instance. The user is created given an IP address in a string,
 * the username, and the addressing information to send packets to. Returns pointer to new
 * user instance if creation successful, or NULL if not (malloc() error).
 */
static User *malloc_user(const char *ip, const char *name, struct sockaddr_in *addr) {

    struct tm *timestamp;
    time_t timer;
    User *new_user;
   
    /* Allocate memory for the struct itself */
    if ((new_user = (User *)malloc(sizeof(User))) != NULL) {
	
	/* Allocate memory for the user members */
	new_user->addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	new_user->channels = ll_create();
	new_user->ip_addr = (char *)malloc(strlen(ip) + 1);
	new_user->username = (char *)malloc(strlen(name) + 1);

	/* Do error checking for malloc(), free all members and return NULL if failed */
	if (new_user->addr == NULL || new_user->channels == NULL || 
	    new_user->ip_addr == NULL || new_user->username == NULL) {
	    if (new_user->addr != NULL) free(new_user->addr);
	    if (new_user->channels != NULL) ll_destroy(new_user->channels, free);
	    if (new_user->ip_addr != NULL) free(new_user->ip_addr);
	    if (new_user->username != NULL) free(new_user->username);
	    free(new_user);
	    return NULL;
	}

	/* Initialize all the members, return the pointer */
	*new_user->addr = *addr;
	strcpy(new_user->ip_addr, ip);
	strcpy(new_user->username, name);
	time(&timer);
	timestamp = localtime(&timer);
	new_user->last_min = timestamp->tm_min;
    }

    return new_user;    
}

/**
 * Updates the time of the specified user's last sent packet to now. Should be
 * invoked every time a packet is received from a connected client.
 */
static void update_user_time(User *user) {
    
    struct tm *timestamp;
    time_t timer;

    if (user != NULL) {
	/* Retrieve current time, update user record */
	time(&timer);
	timestamp = localtime(&timer);
	user->last_min = timestamp->tm_min;
    }
}

/**
 * Destroys the user instance by freeing & returning all memory it reserved back
 * to the heap.
 */
static void free_user(User *user) {
    
    if (user != NULL) {
	/* Free all reserved memory within instance */
	free(user->addr);
	ll_destroy(user->channels, free);
	free(user->ip_addr);
	free(user->username);
	free(user);
    }
}

/**
 * Creates a new instance of a connected server by allocating memory and returns a pointer to
 * the new server instance. The server is created given an IP address in a string and the
 * addressing information to send packets to. Returns a pointer to new server instance if creation
 * was successful, or NULL if not (malloc() error).
 */
static Server *malloc_server(const char *ip, struct sockaddr_in *addr) {

    Server *new_server;

    /* Allocate memory for the struct itself */
    if ((new_server = (Server *)malloc(sizeof(Server))) != NULL) {
	
	/* Allocate memory for the server members */
	new_server->addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	new_server->ip_addr = (char *)malloc(strlen(ip) + 1);

	/* Do error checking for malloc(), free memory if failed */
	if (new_server->addr == NULL || new_server->ip_addr == NULL) {
	    if (new_server->addr != NULL) free(new_server->addr);
	    if (new_server->ip_addr != NULL) free(new_server->ip_addr);
	    free(new_server);
	    return NULL;
	}

	/* Initialize all the members, return the pointer */
	*new_server->addr = *addr;
	strcpy(new_server->ip_addr, ip);
    }

    return new_server;
}

/**
 * Updates the time of the specified server's last received S2S request to now. Needed
 * for soft-state server tracking to prevent network failures.
 */
static void update_server_time(Server *server) {
    
    struct tm *timestamp;
    time_t timer;

    if (server != NULL) {
	/* Retrieve current time, update server record */
	time(&timer);
	timestamp = localtime(&timer);
	server->last_min = timestamp->tm_min;
    }
}

/**
 * Destroys the server instance by freeing & returning all memory it reserved back
 * to the heap.
 */
static void free_server(Server *server) {
    
    if (server != NULL) {
	/* Free all memory within the instance */
	free(server->addr);
	free(server->ip_addr);
	free(server);
    }
}

/**
 * Locates all of the specified neighboring server(s), and checks to see if they exist.
 * Then creates a server struct for each neighbor and adds it into the neighboring
 * hashmap. Returns 1 if all malloc() and hashmap additions are successful, 0 if not.
 */
static int add_neighbors(char *args[], int n) {
    
    struct hostent *host_end;
    struct sockaddr_in addr;
    Server *server;
    char buffer[128];
    int i;
    
    /* If no args given, do nothing */
    if (n == 0)
	return 1;

    for (i = 0; i < n; i += 2) {
	/* Verify that the given address exists, report error if not */
	if ((host_end = gethostbyname(args[i])) == NULL) {
	    fprintf(stderr, "[Server]: Failed to locate the server at %s:%s\n",
		    args[i], args[i + 1]);
	    exit(0);
	}

	/* Create server address struct, set internet family, address, & port number */
	memset((char *)&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	memcpy((char *)&addr.sin_addr, (char *)host_end->h_addr_list[0], host_end->h_length);
	addr.sin_port = htons(atoi(args[i + 1]));
	sprintf(buffer, "%s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	/* Create the server struct, add it into the hashmap */
	if ((server = malloc_server(buffer, &addr)) == NULL)
	    return 0;
	if (!hm_put(neighbors, buffer, server, NULL))
	    return 0;
    }
    
    return 1;	/* Successful return */
}

/**
 * Adds the specified ID into the message ID queue.
 */
static void queue_id(long id) {
    
    id_cache[curr_index++] = id;
    if (curr_index >= MSGQ_SIZE)
	curr_index = 0;
}

/**
 * Generates and returns a random long integer; used for the ID member inside the
 * server-to-server SAY packet. Generated by reading bytes from /dev/urandom.
 */
static long generate_id(void) {
    
    FILE *fd;
    int res;
    long num;
    
    /* Opens and reads bytes from /dev/urandom */
    if ((fd = fopen("/dev/urandom", "r")) == NULL)
	return 10000L;
    if ((res = fread(&num, sizeof(num), 1, fd)) < 0)
	return 20000L;
    /* Close descriptor, queue the id, return number */
    fclose(fd);
    queue_id(num);
    return num;
}

/**
 * Verifies whether the specified ID is unique; compares the ID with all the IDs
 * inside the server's recently received message IDs. Returns 1 if unique, 0 if
 * not (is a duplicate, indicating a loop).
 */
static int id_unique(long id) {
    
    int i;
    for (i = 0; i < MSGQ_SIZE; i++)
	if (id_cache[i] == id)
	    return 0;	/* Duplicate found, return 0 */
    return 1;
}

/**
 * Allocates and returns a socket address struct of the given ip address to
 * send packets to. The IP address string is expected to be in the format
 * '127.0.0.1:8080'. The user is responsible for freeing the pointer.
 */
static struct sockaddr_in *get_addr(char *ip_addr) {

    struct sockaddr_in *addr;
    struct hostent *host_end;
    char hostname[32], port[16];
    char *res;
    int i;

    /* Extract the hostname and port number */
    if ((res = strrchr(ip_addr, ':')) == NULL)
	return NULL;
    strcpy(port, res + 1);
    i = res - ip_addr;
    strncpy(hostname, ip_addr, i);
    hostname[i] = '\0';

    /* Locate the hostname, return NULL if not found */
    if ((host_end = gethostbyname(hostname)) == NULL)
	return NULL;

    /* Initialize and set the address struct members, return the struct */
    if ((addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in))) == NULL)
	return NULL;
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    memcpy((char *)&(addr->sin_addr), (char *)host_end->h_addr_list[0], host_end->h_length);
    addr->sin_port = htons(atoi(port));

    return addr;
}

/**
 * Checks to see if this server is a leaf in the channel sub-tree, given the
 * specified channel name. The server is a leaf if only one neighbor is
 * subscribed, and no clients are currently listening. Returns 1 if is a leaf,
 * or 0 if not.
 */
static int remove_server_leaf(char *channel) {
    
    LinkedList *servers, *users;
    Server *server;
    int res = 0;
    struct request_s2s_leave leave_packet;

    /* No neighbors, do nothing */
    if (hm_isEmpty(neighbors))
	return 0;

    /* Retrieve the list of subscribed servers */
    (void)hm_get(r_table, channel, (void **)&servers);
    if (hm_get(channels, channel, (void **)&users)) {
	/* Server has no other servers or clients listening */
	if (ll_size(servers) < 2L && ll_isEmpty(users))
	    res = 1;
    } else {
	/* Server has no other servers listening */
	if (ll_size(servers) < 2L)
	    res = 1;
    }

    if (!res) return res;   /* Server not a leaf, return */

    /* Initialize & set S2S leave request packet members */
    memset(&leave_packet, 0, sizeof(leave_packet));
    leave_packet.req_type = REQ_S2S_LEAVE;
    strncpy(leave_packet.req_channel, channel, (CHANNEL_MAX - 1));

    /* Remove channel from server subscription list */
    (void)hm_remove(r_table, channel, (void **)&users);
    if (ll_isEmpty(users)) {  /* Destroy the stored LL */
	ll_destroy(users, NULL);
	return 1;
    }
    /* Extract the only neighboring subscribed server */
    ll_removeFirst(users, (void **)&server);
    ll_destroy(users, NULL);
	
    /* Send S2S leave request to neighboring server */
    sendto(socket_fd, &leave_packet, sizeof(leave_packet), 0,
	    (struct sockaddr *)server->addr, sizeof(*server->addr));
    /* Log the sent packet */
    fprintf(stdout, "%s %s send S2S LEAVE %s\n",
	    server_addr, server->ip_addr, leave_packet.req_channel);
    return res;
}    

/**
 * Floods all the neighboring servers with an S2S JOIN request given the specified
 * channel name and the sender's IP address. The sender is skipped over; no packet
 * needs to be sent back to the sender.
 */
static void neighbor_flood_channel(char *channel, char *sender_ip) {
    
    Server *server;
    struct request_s2s_join join_packet;
    char **addrs;
    long i, len;

    /* Get the array of neighboring server IPs, return if malloc() fails */
    if ((addrs = hm_keyArray(neighbors, &len)) == NULL) {
	fprintf(stdout, "%s Failed to flood server(s), memory allocation failed\n",
	    server_addr);
	return;
    }

    /* Initializes & sets the packet's contents */
    memset(&join_packet, 0, sizeof(join_packet));
    join_packet.req_type = REQ_S2S_JOIN;
    strncpy(join_packet.req_channel, channel, (CHANNEL_MAX - 1));

    /* Send the packet to each of the connecting servers */
    /* Do not send it to the server that it received from */
    for (i = 0L; i < len; i++) {
	if (!hm_get(neighbors, addrs[i], (void **)&server))
	    continue;
	if (strcmp(server->ip_addr, sender_ip)) {
	    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		    (struct sockaddr *)server->addr, sizeof(*server->addr));
	    /* Log the sent packet */
	    fprintf(stdout, "%s %s send S2S JOIN %s\n",
		    server_addr, server->ip_addr, channel);
	}
    }

    free(addrs);
}

/**
 * Refreshes all S2S joins by sending S2S join requests for every channel the server
 * is subscribe to to every one of its neighboring servers. Invoked every so often to
 * guard against network failures.
 */
static void refresh_s2s_joins(void) {
    
    char **chs;
    long i, len = 0L;

    /* Get an array of the server's subscribed channels */
    /* If server is not subscribed to any channels, don't bother with scan */
    if ((chs = hm_keyArray(r_table, &len)) == NULL) {
	if (!hm_isEmpty(r_table))  /* malloc() failure, print error and return */
	    fprintf(stdout, "%s Failed to refresh S2S join(s), memory allocation failed\n",
		    server_addr);
	return;
    }

    /* Send an S2S join to all neighbors for each channel */
    for (i = 0L; i < len; i++)
	neighbor_flood_channel(chs[i], server_addr);
    free(chs);
}

/**
 * Adds the specified channel into the neighboring server's subscription list
 * by allocating memory for space in the hashmap of channels, and creates a
 * linked list to hold the subscribed servers. Also adds all neighboring servers
 * to the list initially. Returns 1 if fully successful, 0 if not (malloc() error(s)).
 */
static int server_join_channel(char *channel) {

    LinkedList *servers = NULL;
    Server *server;
    char **addrs = NULL;
    long i, len;

    /* Create the list of listening servers */
    if ((servers = ll_create()) == NULL)
	goto error;
    if ((addrs = hm_keyArray(neighbors, &len)) == NULL)
	goto error;

    /* Adds each connected server into the list */
    for (i = 0L; i < len; i++) {
	if (!hm_get(neighbors, addrs[i], (void **)&server))
	    continue;
	/* Checks for malloc() errors */
	if (!ll_add(servers, server))
	    goto error;
    }

    /* Add the list of neighbors into the subscription hashmap */
    if (!hm_put(r_table, channel, servers, NULL))
	goto error;

    free(addrs);
    return 1;	/* All addition(s) were successful */

error:
    /* Free any allocated memory, return 0 */
    if (servers != NULL) ll_destroy(servers, NULL);
    if (addrs != NULL) free(addrs);
    return 0;
}

/**
 * Sends a packet containing the error message 'msg' to the client with the specified
 * address information. Also logs the packet sent to the address with the error
 * message.
 */
static void server_send_error(struct sockaddr_in *addr, const char *msg) {
    
    struct text_error error_packet;

    /* Initialize the error packet; set the type */
    memset(&error_packet, 0, sizeof(error_packet));
    error_packet.txt_type = TXT_ERROR;
    /* Copy the error message into packet, ensure length does not exceed limit allowed */
    strncpy(error_packet.txt_error, msg, (SAY_MAX - 1));
    /* Send packet off to user */
    sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)addr, sizeof(*addr));
    /* Log the error message */
    fprintf(stdout, "%s %s:%d send ERROR \"%s\"\n", server_addr,
		inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), msg);
}

/**
 * Server receives an authentication packet; the server responds to the client telling them
 * if the username is currently occupied or not.
 */
static void server_verify_request(const char *packet, const char *client_ip, struct sockaddr_in *client) {

    User *user;
    char **ip_list = NULL;
    int res = 1;
    long i, len = 0L;
    struct sockaddr_in *forward = NULL;
    struct text_verify respond_packet;
    struct request_s2s_verify *s2s_verify = NULL;
    struct request_verify *verify_packet = (struct request_verify *) packet;

    /* Log the received packet */
    fprintf(stdout, "%s %s recv Request VERIFY %s\n",
	    server_addr, client_ip, verify_packet->req_username);
    
    /* Retrieve list of users to check for verification */
    if ((ip_list = hm_keyArray(users, &len)) == NULL)
	if (!hm_isEmpty(users))
	    return;
    
    /* Check each username for uniqueness */
    for (i = 0L; i < len; i++) {
	(void)hm_get(users, ip_list[i], (void **)&user);
	if (!strcmp(verify_packet->req_username, user->username)) {
	    res = 0;	/* Username taken, break from loop */
	    break;
	}
    }
    free(ip_list);  /* Free allocated memory */

    /* If the username is valid, and there are neighboring servers to check, */
    /* Forward the packet to the next server in the list */
    if (!hm_isEmpty(neighbors) && res) {
	
	/* Calculate size of the packet, allocate the memory */
	int size = (sizeof(struct request_s2s_verify) +
		(sizeof(struct ip_address) * (hm_size(neighbors) - 1)));
	if ((s2s_verify = (struct request_s2s_verify *)malloc(size)) == NULL)
	    goto error;
	/* Get list of neighboring servers' IP addresses */
	if ((ip_list = hm_keyArray(neighbors, &len)) == NULL)
	    goto error;

	/* Initialize and set the packet members */
	memset(s2s_verify, 0, size);
	s2s_verify->req_type = REQ_S2S_VERIFY;
	s2s_verify->id = generate_id();
	strcpy(s2s_verify->req_username, verify_packet->req_username);
	strncpy(s2s_verify->client.ip_addr, client_ip, (IP_MAX - 1));
	s2s_verify->nto_visit = ((int)len - 1);
	/* Create the list of IP addresses to visit */
	for (i = 0; i < s2s_verify->nto_visit; i++)
	    strncpy(s2s_verify->to_visit[i].ip_addr, ip_list[i + 1], (IP_MAX - 1));
	/* Exclude the first IP address from list, send the packet to this address */
	if ((forward = get_addr(ip_list[0])) == NULL)
	    goto error;
	
	/* Forward the S2S verify request, log the sent packet */
	sendto(socket_fd, s2s_verify, size, 0, (struct sockaddr *)forward, sizeof(*forward));
	fprintf(stdout, "%s %s send S2S VERIFY %s\n", server_addr, ip_list[0], s2s_verify->req_username);
	
	/* Free all allocated memory and return */
	free(forward);
	free(ip_list);
	free(s2s_verify);
	return;
    }

    /* Otherwise, send the response packet back to the client */
    /* Initialize and set packet members */
    memset(&respond_packet, 0, sizeof(respond_packet));
    respond_packet.txt_type = TXT_VERIFY;
    respond_packet.valid = res;
    /* Send packet back to client, log the request */
    sendto(socket_fd, &respond_packet, sizeof(respond_packet), 0,
		(struct sockaddr *)client, sizeof(*client));
    return;

error:
    /* Send error back to client */
    server_send_error(client, "Verification failed.");
    /* Free all allocated memory */
    if (ip_list != NULL) free(ip_list);
    if (forward != NULL) free(forward);
    if (s2s_verify != NULL) free(s2s_verify);
}

/**
 * Server receives a login packet; the server allocates memory and creates an instance of the
 * new user and connects them to the server.
 */
static void server_login_request(const char *packet, char *client_ip, struct sockaddr_in *addr) {

    User *user = NULL;
    char name[USERNAME_MAX];
    struct request_login *login_packet = (struct request_login *) packet;

    /* Copy username into buffer, ensures name length does not exceed max allowed */
    memset(name, 0, sizeof(name));
    strncpy(name, login_packet->req_username, (USERNAME_MAX - 1));

    /* Create a new instance of the user */
    /* Send error back to client if malloc() failed, log the error */
    if ((user = malloc_user(client_ip, name, addr)) == NULL)
	goto error;

    /* Add the new user into the users hashmap */
    /* Send error back to client if failed, log the error */
    if (!hm_put(users, client_ip, user, NULL))
	goto error;

    /* Log the user login information */
    fprintf(stdout, "%s %s recv Request LOGIN %s\n",
	    server_addr, user->ip_addr, user->username);
    return;

error:
    /* Send error back to client */
    server_send_error(addr, "Failed to log into the server.");
    /* Free all allocated memory */
    if (user != NULL) free_user(user);
}

/**
 * Server receives a join packet; the server adds the client to the requested channel, so
 * that they can now receive messages from other subscribed clients.
 */
static void server_join_request(const char *packet, char *client_ip) {
    
    User *user, *tmp;
    LinkedList *user_list = NULL;
    int ch_len;
    long i;
    char *joined = NULL;
    char buffer[256];
    struct request_join *join_packet = (struct request_join *) packet;

    /* Assert that the user is currently logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    /* Update user time, log received join request */
    update_user_time(user);
    fprintf(stdout, "%s %s recv Request JOIN %s %s\n", server_addr,
		user->ip_addr, user->username, join_packet->req_channel);

    /* Set the channel name length; shorten it down if exceeds max length allowed */
    ch_len = ((strlen(join_packet->req_channel) > (CHANNEL_MAX - 1)) ?
				(CHANNEL_MAX - 1) : strlen(join_packet->req_channel));
    /* Allocate memory from heap for name, report and log error if failed */
    if ((joined = (char *)malloc(ch_len + 1)) == NULL)
	goto error;

    /* Extract the channel name from packet */
    memcpy(joined, join_packet->req_channel, ch_len);
    joined[ch_len] = '\0';

    /* Add this channel to the neighboring server's subscription list */
    if (!hm_isEmpty(neighbors)) {
	if (!hm_containsKey(r_table, joined)) {
	    if (!server_join_channel(joined))
		goto error;
	    neighbor_flood_channel(joined, server_addr);
	}
    }

    /* Add the channel to user's subscribed list, send error if failed, log error */
    if (!ll_add(user->channels, joined))
	goto error;

    /* User has joined a channel that does not exist */
    if (!hm_get(channels, joined, (void **)&user_list)) {

	/* Create the new channel list, send error back if failed, log the error */
	if ((user_list = ll_create()) == NULL)
	    goto error;

	/* Add the user to the list, send error back if failed, log the error */
	if (!ll_add(user_list, user))
	    goto error;

	/* Add the channel to the server's channel collection */
	/* Send error back to client if failed, log the error */
	if (!hm_put(channels, joined, user_list, NULL))
	    goto error;

    /* User has joined a channel that already exists */
    } else {
	
	/* Check to see if user is already subscribed; makes sure not to add duplicate instance(s) */
	for (i = 0L; i < ll_size(user_list); i++) {
	    (void)ll_get(user_list, i, (void **)&tmp);
	    if (strcmp(user->ip_addr, tmp->ip_addr) == 0)
		return;
	}

	/* User was not found, so add them to subscription list */
	/* If failed, send error back to client, log the error */
	if (!ll_add(user_list, user))
	    goto error;
    }
    return;

error:
    /* Send error back to client */
    sprintf(buffer, "Failed to join %s.", join_packet->req_channel);
    server_send_error(user->addr, buffer);
    /* Free all allocated memory */
    if (joined != NULL) free(joined);
    if (user_list != NULL) ll_destroy(user_list, NULL);
}

/**
 * Server recieves a leave packet from a client; the server removes the specified
 * channel from the user's subscription list and deletes the channel if becomes
 * empty.
 */
static void server_leave_request(const char *packet, char *client_ip) {

    User *user, *tmp;
    LinkedList *user_list;
    int removed = 0;
    long i;
    char *ch;
    char channel[CHANNEL_MAX], buffer[256];
    struct request_leave *leave_packet = (struct request_leave *) packet;

    /* Assert that the user requesting is currently logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    update_user_time(user);

    /* Copy into buffer, ensure the channel name length does not exceed maximum allowed */
    memset(channel, 0, sizeof(channel));
    strncpy(channel, leave_packet->req_channel, (CHANNEL_MAX - 1));
    /* Assert that the channel currently exists */
    /* If not, report error back to user, log the error */
    if (!hm_get(channels, channel, (void **)&user_list)) {
	sprintf(buffer, "No channel by the name %s.", leave_packet->req_channel);
	server_send_error(user->addr, buffer);
	return;
    }

    /* Next, remove the requested channel from the user's list of subscribed channels */
    for (i = 0L; i < ll_size(user->channels); i++) {
	(void)ll_get(user->channels, i, (void **)&ch);
	if (strcmp(channel, ch) == 0) {
	    /* Channel found, remove it from list and free reserved memory */
	    ll_remove(user->channels, i, (void **)&ch);
	    fprintf(stdout, "%s %s recv Request LEAVE %s %s\n", server_addr,
			    user->ip_addr, user->username, ch);
	    free(ch);
	    removed = 1;
	    break;
	}
    }

    /* Next, remove pointer of user from the channel's list of subscribed users */
    /* Ensures no more messages will be sent to the unsubscribed user */
    for (i = 0L; i < ll_size(user_list); i++) {
	(void)ll_get(user_list, i, (void **)&tmp);
	if (strcmp(user->ip_addr, tmp->ip_addr) == 0) {
	    /* User found, remove them from subscription list */
	    (void)ll_remove(user_list, i, (void **)&tmp);
	    break;
	}
    }

    if (!removed) {
	/* User was not removed, wasn't subscribed to channel to begin with */
	/* Send a message back to user notifying them, log the error */
	sprintf(buffer, "You are not subscribed to %s.", channel);
	server_send_error(user->addr, buffer);
	return;
    }

    /* If the channel the user left becomes empty, remove it from channel list */
    if (ll_isEmpty(user_list) && strcmp(channel, DEFAULT_CHANNEL)) {
	/* Free all memory reserved by deleted channel */
	fprintf(stdout, "%s Removed the empty channel %s\n", server_addr, channel);
	(void)hm_remove(channels, channel, (void **)&user_list);
	ll_destroy(user_list, NULL);
    }

    /* Server removes itself from channel sub-tree if leaf */
    (void)remove_server_leaf(channel);
}

/**
 * Sends a say packet to each subscribed client inside the list 'users', broadcasting
 * the message.
 */
static int broadcast_message(LinkedList *users, char *username, char *channel, char *text) {
    
    User **listeners;
    long i, len = 0L;
    struct text_say msg_packet;

    /* NULL checking */
    if (users == NULL)
	return 0;

    /* Get list of users, return 0 if malloc() fails */
    if ((listeners = (User **)ll_toArray(users, &len)) == NULL)
	if (!ll_isEmpty(users))
	    return 0;

    /* Initialize the SAY packet to send; set the type, channel, and username */
    memset(&msg_packet, 0, sizeof(msg_packet));
    msg_packet.txt_type = TXT_SAY;
    strncpy(msg_packet.txt_channel, channel, (CHANNEL_MAX - 1));
    strncpy(msg_packet.txt_username, username, (USERNAME_MAX - 1));
    strncpy(msg_packet.txt_text, text, (SAY_MAX - 1));

    /* Send the packet to each user listening on the channel */
    for (i = 0L; i < len; i++)
	sendto(socket_fd, &msg_packet, sizeof(msg_packet), 0,
		(struct sockaddr *)listeners[i]->addr, sizeof(*listeners[i]->addr));
    /* Free reserved memory */
    free(listeners);

    return 1;	/* Successful broadcast(s), return 1 */
}

/**
 * Server receiveds a say packet from a client; the server broadcasts the message
 * back to all connected clients subscribed to the requested channel by sending
 * a packet to each of the subscribed clients.
 */
static void server_say_request(const char *packet, char *client_ip) {
    
    User *user;
    Server *server;
    LinkedList *ch_users;
    long i;
    char buffer[256];
    struct request_say *say_packet = (struct request_say *) packet;
    struct request_s2s_say s2s_say;

    /* Assert user is logged in; do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    /* Assert that the channel exists; do nothing if not */
    if (!hm_get(channels, say_packet->req_channel, (void **)&ch_users))
	return;
    /* Update user time, log received say request */
    update_user_time(user);
    fprintf(stdout, "%s %s recv Request SAY %s %s \"%s\"\n", server_addr, user->ip_addr,
		user->username, say_packet->req_channel, say_packet->req_text);

    /* Respond to user with error message if malloc() failure, log the error */
    if (!broadcast_message(ch_users, user->username, say_packet->req_channel, say_packet->req_text)) {
	sprintf(buffer, "Failed to send the message.");
	server_send_error(user->addr, buffer);
	return;
    }

    /* Initialize the S2S SAY packet to send; set the ID, channel, and username */
    memset(&s2s_say, 0, sizeof(s2s_say));
    s2s_say.req_type = REQ_S2S_SAY;
    s2s_say.id = generate_id();
    strncpy(s2s_say.req_channel, say_packet->req_channel, (CHANNEL_MAX - 1));
    strncpy(s2s_say.req_username, user->username, (USERNAME_MAX - 1));
    strncpy(s2s_say.req_text, say_packet->req_text, (SAY_MAX - 1));

    /* Get the list of listening neighboring servers */
    if (!hm_get(r_table, say_packet->req_channel, (void **)&ch_users))
	return;
    /* Send the S2S say packet to all connecting servers */
    for (i = 0L; i < ll_size(ch_users); i++) {
	(void)ll_get(ch_users, i, (void **)&server);
	sendto(socket_fd, &s2s_say, sizeof(s2s_say), 0,
		(struct sockaddr *)server->addr, sizeof(*server->addr));
	/* Log the S2S packet sent */
	fprintf(stdout, "%s %s send S2S SAY %s %s \"%s\"\n",
		server_addr, server->ip_addr, s2s_say.req_username,
		s2s_say.req_channel, s2s_say.req_text);
    }
}

/**
 * Server receives a list packet from a client; the server compiles a list of
 * all the channels currently available on the server, then sends the packet
 * back to the client.
 */
static void server_list_request(char *client_ip) {

    User *user;
    int size;
    long i, j, len = 0L;
    char **array = NULL;
    struct sockaddr_in *forward;
    struct request_s2s_list *s2s_list = NULL;
    struct text_list *list_packet = NULL;

    /* Assert that the user is logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    /* Update user time, log list request */
    update_user_time(user);
    fprintf(stdout, "%s %s recv Request LIST %s\n", server_addr,
		user->ip_addr, user->username);

    /* Retrieve the complete list of channel names */
    /* Send error message back to client if failed (malloc() error), log the error */
    if ((array = hm_keyArray(channels, &len)) == NULL)
	if (!hm_isEmpty(channels))
	    goto error;
    
    /* If there are neighboring servers, we must send an S2S request */
    if (!hm_isEmpty(neighbors)) {
	
	/* Calculate the size of the packet, allocate the memory */
	size = (sizeof(struct request_s2s_list) +
		(sizeof(struct s2s_list_container) *
		(hm_size(channels) + (hm_size(neighbors) - 1))));
	if ((s2s_list = (struct request_s2s_list *)malloc(size)) == NULL)
	    goto error;

	/* Initialize and set the packet members */
	memset(s2s_list, 0, sizeof(*s2s_list));
	s2s_list->req_type = REQ_S2S_LIST;
	s2s_list->id = generate_id();
	strncpy(s2s_list->client.ip_addr, client_ip, (IP_MAX - 1));
	s2s_list->nchannels = (int)len;
	
	/* Copy all channels into the packet */
	for (i = 0L; i < len; i++)
	    strncpy(s2s_list->payload[i].element, array[i], (CHANNEL_MAX - 1));
	free(array);
	
	/* Get array of neighboring IP addresses */
	if ((array = hm_keyArray(neighbors, &len)) == NULL)
	    goto error;
	/* Copy the neighboring IPs into packet to visit */
	j = i;
	s2s_list->nto_visit = ((int)len - 1);   ///FIXME THIS SECTION IS CAUSING THE ERROR
	for (i = 0; i < s2s_list->nto_visit; i++)
	    strncpy(s2s_list->payload[j + i].element, array[i + 1], (CHANNEL_MAX - 1));
	
	/* Get the address of the server to send request to */
	if ((forward = get_addr(array[0])) == NULL)
	    goto error;

	/* Send the packet, log the sent packet */
	sendto(socket_fd, s2s_list, size, 0, (struct sockaddr *)forward, sizeof(*forward));
	fprintf(stdout, "%s %s send S2S LIST\n", server_addr, array[0]);
	/* Free all allocated memory */
	free(array);
	free(s2s_list);
	free(forward);
	return;
    }

    /* Calculate the exact size of packet to send back */
    size = sizeof(struct text_list) + (sizeof(struct channel_info) * len);
    /* Allocate memory for the packet using calculated size */
    /* Send error back to user if failed (malloc() error), log the error */
    if ((list_packet = (struct text_list *)malloc(size)) == NULL)
	goto error;

    /* Initialize the packet; set the type and number of channels */
    memset(list_packet, 0, size);
    list_packet->txt_type = TXT_LIST;
    list_packet->txt_nchannels = (int)len;
    /* Copy each channel name from the list into the packet */
    for (i = 0L; i < len; i++)
	strncpy(list_packet->txt_channels[i].ch_channel, array[i], (CHANNEL_MAX - 1));

    /* Send the packet to client, log the listing event */
    sendto(socket_fd, list_packet, size, 0,
		(struct sockaddr *)user->addr, sizeof(*user->addr));

    /* Return all allocated memory back to heap */
    free(array);
    free(list_packet);
    return;

error:
    /* Send error back to client */
    server_send_error(user->addr, "Failed to list the channels.");
    /* Free all allocated memory */
    if (array != NULL) free(array);
    if (s2s_list != NULL) free(s2s_list);
    if (list_packet != NULL) free(list_packet);
}

/**
 * Server receives a who packet from a client; the server compiles a list of all
 * the users currently subscribed to the requested channel, then sends the packet
 * back to the client.
 */
static void server_who_request(const char *packet, char *client_ip) {

    User *user, **user_list = NULL;
    LinkedList *subscribers;
    char **array= NULL;
    int size;
    long i, j, len = 0L;
    char buffer[256];
    struct sockaddr_in *forward;
    struct request_s2s_who *s2s_who = NULL;
    struct text_who *send_packet = NULL;
    struct request_who *who_packet = (struct request_who *) packet;

    /* Assert that the user is logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    /* Update user time, log who request */
    update_user_time(user);
    fprintf(stdout, "%s %s recv Request WHO %s %s\n", server_addr,
		user->ip_addr, user->username, who_packet->req_channel);

    /* Assert that the channel requested exists, send error back if it doesn't, log the error */
    if (!hm_get(channels, who_packet->req_channel, (void **)&subscribers)) {
	sprintf(buffer, "No channel by the name %s.", who_packet->req_channel);
	server_send_error(user->addr, buffer);
	return;
    }

    /* Retrieve the list of users subscribed to the requested channel */
    /* Send error message back to client if failed (malloc() error), log the error */
    if ((user_list = (User **)ll_toArray(subscribers, &len)) == NULL)
	if (!ll_isEmpty(subscribers))
	    goto error;
    
    /* If there are neighboring servers, we must send an S2S request to them */
    if (!hm_isEmpty(neighbors)) {
	
	/* Calculate the size of the packet, allocate the memory */
	size = (sizeof(struct request_s2s_who) +
		(sizeof(struct s2s_who_container) *
		(len + (hm_size(neighbors) - 1))));
	if ((s2s_who = (struct request_s2s_who *)malloc(size)) == NULL)
	    goto error;

	/* Initialize and set the packet members */
	memset(s2s_who, 0, sizeof(*s2s_who));
	s2s_who->req_type = REQ_S2S_WHO;
	s2s_who->id = generate_id();
	strncpy(s2s_who->channel, who_packet->req_channel, (CHANNEL_MAX - 1));
	strncpy(s2s_who->client.ip_addr, client_ip, (IP_MAX - 1));
	
	/* Copy the usernames into the packet */
	s2s_who->nusers = (int)len;
	for (i = 0L; i < len; i++)
	    strncpy(s2s_who->payload[i].element, user_list[i]->username, (USERNAME_MAX - 1));
	free(user_list);

	/* Get array of neighboring IP addresses to visit */
	if ((array = hm_keyArray(neighbors, &len)) == NULL)
	    goto error;
	/* Copy all IPs into the visitation list */
	j = i;
	s2s_who->nto_visit = ((int)len - 1);///FIXME THIS SECTION IS CAUSING THE ERROR
	for (i = 0; i < s2s_who->nto_visit; i++)
	    strncpy(s2s_who->payload[j + i].element, array[i + 1], (USERNAME_MAX - 1));
	
	/* Get the address of the server to send packet to */
	if ((forward = get_addr(array[0])) == NULL)
	    goto error;
	/* Send the packet, log the sent packet */
	sendto(socket_fd, s2s_who, size, 0, (struct sockaddr *)forward, sizeof(*forward));
	fprintf(stdout, "%s %s send S2S WHO %s\n", server_addr, array[0], who_packet->req_channel);

	/* Free all allocated memory */
	free(forward);
	free(array);
	free(s2s_who);
	return;
    }

    /* Calculate the exact size of packet to send back */
    size = sizeof(struct text_who) + (sizeof(struct user_info) * len);
    /* Allocate memory for the packet using calculated size */
    /* Send error back to user if failed (malloc() error), log the error */
    if ((send_packet = (struct text_who *)malloc(size)) == NULL)
	goto error;

    /* Initialize the packet; set the type, number of users, and channel */
    memset(send_packet, 0, size);
    send_packet->txt_type = TXT_WHO;
    send_packet->txt_nusernames = (int)len;
    strncpy(send_packet->txt_channel, who_packet->req_channel, (CHANNEL_MAX - 1));
    /* Copy each username from subscription list into packet */
    for (i = 0L; i < len; i++)
	strncpy(send_packet->txt_users[i].us_username, user_list[i]->username, (USERNAME_MAX - 1));

    /* Send the packet to client, log the listing event */
    sendto(socket_fd, send_packet, size, 0,
		(struct sockaddr *)user->addr, sizeof(*user->addr));
    /* Return all allocated memory back to heap */
    free(user_list);
    free(send_packet);
    return;

error:
    /* Send error back to client */
    sprintf(buffer, "Failed to list users on %s.", who_packet->req_channel);
    server_send_error(user->addr, buffer);
    /* Free all allocated memory */
    if (user_list != NULL) free(user_list);
    if (array != NULL) free(array);
    if (s2s_who != NULL) free(s2s_who);
    if (send_packet != NULL) free(send_packet);
}

/**
 * Server receives a keep-alive packet from a client; the server simply updates the
 * user's last sent packet time so that they are not logged out due to inactivity.
 */
static void server_keep_alive_request(char *client_ip) {

    User *user;

    /* Assert that the user is logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    /* Update user time, log keep alive request */	
    update_user_time(user);
    fprintf(stdout, "%s %s recv Request KEEP ALIVE %s\n",
		    server_addr, user->ip_addr, user->username);
}

/**
 * Manually removes the specified user from the server database. Logs the user
 * out and removes all instances of the user from all their subscribed channels.
 * All reserved memory associated with the user is also freed and returned to
 * the heap.
 */
static void logout_user(User *user) {

    User *tmp;
    LinkedList *user_list;
    long i;
    char *ch;

    /* For each of the user's subscribed channels */
    /* Remove user from each of the existing channel's subscription list */
    while (ll_removeFirst(user->channels, (void **)&ch)) {
	
	/* Error catch: channel does not actually exist, continue */
	if (!hm_get(channels, ch, (void **)&user_list)) {
	    free(ch);
	    continue;
	}

	/* Perform a linear search in channel's subscription list for user */
	for (i = 0L; i < ll_size(user_list); i++) {
	    (void)ll_get(user_list, i, (void **)&tmp);
	    /* User found, remove them from the list */
	    if (strcmp(user->ip_addr, tmp->ip_addr) == 0) {
		(void)ll_remove(user_list, i, (void **)&tmp);
		break;
	    }
	}

	/* If the channel is now empty, server should now delete it */
	if (ll_isEmpty(user_list) && strcmp(ch, DEFAULT_CHANNEL)) {
	    (void)hm_remove(channels, ch, (void **)&user_list);
	    ll_destroy(user_list, NULL);
	    fprintf(stdout, "%s Removed the empty channel %s\n", server_addr, ch);
	}
	/* Removes server from channel sub-tree if leaf */
	(void)remove_server_leaf(ch);
	/* Free allocated memory */
	free(ch);
    }
    /* Free allocated memory */
    free_user(user);
}

/**
 * Server receives a logout packet from a client; server removes the user from the
 * user database and any instances of them from all the channels.
 */
static void server_logout_request(char *client_ip) {

    User *user;

    /* Assert the user is logged in, do nothing if not */
    if (!hm_remove(users, client_ip, (void **)&user))
	return;
    /* Log logout request, logout the user */
    fprintf(stdout, "%s %s recv Request LOGOUT %s\n",
		server_addr, user->ip_addr, user->username);
    logout_user(user);
}

/**
 * Checks the specified clock minute and determines whether the client/server
 * is inactive. If the clock minute is past the refresh rate, then the client or
 * server is deemed inactive. Return 1 if inactive, 0 if not.
 */
static int is_inactive(short last_min) {

    struct tm *timestamp;
    time_t timer;
    int diff;

    /* Retrieve the current time */
    time(&timer);
    timestamp = localtime(&timer);
    /* Calculate the number of minutes the client last sent a packet */
    if (timestamp->tm_min >= last_min)
	diff = (timestamp->tm_min - last_min);
    else
	diff = ((60 - last_min) + timestamp->tm_min);
    /* Check and return user inactivity */
    return (diff >= REFRESH_RATE);
}

/**
 * Performs a scan on all the currently connected clients and determines for
 * each one whether the client is inactive or not. If inactive, the client
 * is forcefully logged out, or ignored if otherwise.
 */
static void logout_inactive_users(void) {
    
    User *user;
    long i, len;
    char **user_list;

    /* If no users are connected, don't bother with the scan */
    if (hm_isEmpty(users))
	return;

    /* Retrieve the list of all connected clients */
    /* Abort the scan if failed (malloc() error), log the error */
    if ((user_list = hm_keyArray(users, &len)) == NULL) {
	fprintf(stdout, "%s Failed to scan for inactive users, memory allocation failed\n",
		server_addr);
	return;
    }

    for (i = 0L; i < len; i++) {
	/* Assert the user exists in the map */
	if (!hm_get(users, user_list[i], (void **)&user))
	    continue;
	/* Determines if the user is inactive */
	if (is_inactive(user->last_min)) {
	    /* User is deemed inactive, logout & remove the user */
	    (void)hm_remove(users, user->ip_addr, (void **)&user);
	    fprintf(stdout, "%s Forcefully logged out inactive user %s\n",
			    server_addr, user->username);
	    logout_user(user);
	}
    }

    /* Free allocated memory */
    free(user_list);
}

/**
 * Performs a scan on all the currently subscribed channels and determines
 * whether each of the neighboring servers are inactive or not. If inactive,
 * the server is removed from the subscription list, or ignored if otherwise.
 */
 static void remove_inactive_servers(void) {
    
    LinkedList *servers;
    Server *server;
    char **chs;
    long i, j, len = 0L;
    
    /* If server channel subscription list is empty, don't bother with scan */
    if (hm_isEmpty(r_table))
	return;

    /* Get the full list of server's subscribed channels, log error if malloc() fails */
    if ((chs = hm_keyArray(r_table, &len)) == NULL) {
	fprintf(stdout, "%s Failed to scan for crashed servers, memory allocation failed\n",
		server_addr);
	return;
    }

    for (i = 0L; i < len; i++) {
	/* Assert that the channel exists */
	if (!hm_get(r_table, chs[i], (void **)&servers))
	    continue;
	for (j = 0L; j < ll_size(servers); j++) {
	    /* Obtain the neighboring subscribed server */
	    (void)ll_get(servers, j, (void **)&server);
	    if (!is_inactive(server->last_min))
		continue;
	    /* Server deemed inactive, remove it from the subscription list */
	    (void)ll_remove(servers, j, (void **)&server);
	    fprintf(stdout, "%s Removed inactive server %s from channel %s\n",
			server_addr, server->ip_addr, chs[i]);
	    /* Remove server from channel sub-tree if becomes a leaf */
	    (void)remove_server_leaf(chs[i]);
	}
    }
    /* Free the allocated memory */
    free(chs);
}

/**
 * Server receives a S2S VERIFY request. Checks the list of users for username uniqueness and
 * replies back to client immediately if invalid. Otherwise, if there are servers that still
 * need to be checked, forward the packet to the next server on the visitation list.
 */
static void server_s2s_verify(const char *packet, char *client_ip) {

    HashMap *ip_set = NULL;
    User *user;
    char **ip_list = NULL;
    long i, len = 0L;
    int unique, size, res = 1;
    struct sockaddr_in *client = NULL;
    struct text_verify verify_response;
    struct request_s2s_verify *forward = NULL;
    struct request_s2s_verify *s2s_verify = (struct request_s2s_verify *) packet;    

    /* Log the received packet */
    fprintf(stdout, "%s %s recv S2S VERIFY %s\n", server_addr, client_ip, s2s_verify->req_username);
    
    /* Only check for username uniqueness if ID is not in cache */
    /* Otherwise, skip; this is to guard against loops */
    if ((unique = id_unique(s2s_verify->id)) != 0) {
	queue_id(s2s_verify->id);
	/* Get list of users to check */
	if ((ip_list = hm_keyArray(users, &len)) == NULL)
	    if (!hm_isEmpty(users))
		goto free;
	/* Iterate through list, check for uniqueness */
	for (i = 0L; i < len; i++) {
	    (void)hm_get(users, ip_list[i], (void **)&user);
	    if (strcmp(s2s_verify->req_username, user->username) == 0) {
		res = 0;    /* Username is taken, break from loop */
		break;
	    }
	}
	free(ip_list);
    }

    /* Get list of neighboring servers */
    if ((ip_list = hm_keyArray(neighbors, &len)) == NULL)
	goto free;
    /* Create a hashmap to store the list */
    if ((ip_set = hm_create(0L, 0.0f)) == NULL)
	goto free;
    
    /* If ID not in cache, add all the neighboring servers' IP addresses */
    if (unique) {
	for (i = 0L; i < len; i++)
	    if (strcmp(ip_list[i], client_ip))
		(void)hm_put(ip_set, ip_list[i], NULL, NULL);
    }
    /* Copy all IP addresses from received packet into hashmap */
    for (i = 0; i < s2s_verify->nto_visit; i++)
	(void)hm_put(ip_set, s2s_verify->to_visit[i].ip_addr, NULL, NULL);

    /* If there are no more servers to visit, send reply back to client */
    if (hm_isEmpty(ip_set) || !res) {
	
	/* Initialize and set packet members */
	memset(&verify_response, 0, sizeof(verify_response));
	verify_response.txt_type = TXT_VERIFY;
	verify_response.valid = res;

	/* Get client's address */
	if ((client = get_addr(s2s_verify->client.ip_addr)) == NULL)
	    goto free;
	/* Send packet to client, log sent packet */
	sendto(socket_fd, &verify_response, sizeof(verify_response), 0,
		(struct sockaddr *)client, sizeof(*client));
	fprintf(stdout, "%s %s send VERIFICATION %s\n",
		server_addr, s2s_verify->client.ip_addr, s2s_verify->req_username);
	goto free;
    }

    /* Calculate size of new forwarding packet, allocate memory */
    size = (sizeof(struct request_s2s_verify) + (sizeof(struct ip_address) * ((int)hm_size(ip_set) - 1)));
    if ((forward = (struct request_s2s_verify *)malloc(size)) == NULL)
	goto free;
    /* Get array of IP addresses to copy into the new packet */
    free(ip_list);
    if ((ip_list = hm_keyArray(ip_set, &len)) == NULL)
	goto free;
    
    /* Initialize and set packet members */
    memset(forward, 0, sizeof(*forward));
    forward->req_type = REQ_S2S_VERIFY;
    forward->id = s2s_verify->id;
    strcpy(forward->req_username, s2s_verify->req_username);
    strcpy(forward->client.ip_addr, s2s_verify->client.ip_addr);
    forward->nto_visit = (int)len - 1;
    /* Copy all IP addresses into packet's visiting list */
    for (i = 1L; i < len; i++)
	strcpy(forward->to_visit[i - 1].ip_addr, ip_list[i]);

    /* Get the address of the next server to forward packet to */
    if ((client = get_addr(ip_list[0])) == NULL)
	goto free;
    /* Send the packet to the server, log the sent packet */
    sendto(socket_fd, forward, size, 0, (struct sockaddr *)client, sizeof(*client));
    fprintf(stdout, "%s %s send S2S VERIFY %s\n",
	    server_addr, ip_list[0], s2s_verify->req_username);
    goto free;

free:
    /* Free all allocated memory */
    if (ip_list != NULL) free(ip_list);
    if (ip_set != NULL) hm_destroy(ip_set, NULL);
    if (client != NULL) free(client);
    if (forward != NULL) free(forward);
    return;
}

/**
 * Server receives a S2S join packet. If the server is not subscribed to the contained
 * channel, it subscribes itself to the channel and forwards the packet to all of its
 * neighboring servers. Otherwise, does nothing.
 */
static void server_s2s_join_request(const char *packet, char *client_ip) {

    Server *server, *sender;
    LinkedList *servers;
    long i;
    struct request_s2s_join *join_packet = (struct request_s2s_join *) packet;

    /* Get neighboring sender */
    if (!hm_get(neighbors, client_ip, (void **)&sender))
	return;
    update_server_time(sender);

    /* Log the received packet */
    fprintf(stdout, "%s %s recv S2S JOIN %s\n",
	    server_addr, client_ip, join_packet->req_channel);

    /* If server is already subscribed, request dies here */
    if (hm_get(r_table, join_packet->req_channel, (void **)&servers)) {
	for (i = 0L; i < ll_size(servers); i++) {
	    (void)ll_get(servers, i, (void **)&server);
	    /* Server already subscribed, return */
	    if (!strcmp(server->ip_addr, client_ip))
		return;
	}
	/* Server not subscribed, add it to list */
	(void)ll_add(servers, sender);
	return;
    }

    /* Adds the channel, and all neighboring servers to subscription map */
    if (!server_join_channel(join_packet->req_channel)) {
	fprintf(stdout, "%s Failed to add channel %s to server's subscription list\n",
		server_addr, join_packet->req_channel);
	return;
    }
    /* Flood all neighboring servers with S2S join request */
    neighbor_flood_channel(join_packet->req_channel, client_ip);
}

/**
 * Server receives an S2S leave packet. The server that sent the packet is
 * removed/unsubscribed from the channel list it wishes to leave. This way,
 * the server wont send messages to this server to avoid loops, or empty
 * server channels.
 */
static void server_s2s_leave_request(const char *packet, char *client_ip) {

    LinkedList *servers;
    Server *server;
    long i;
    struct request_s2s_leave *leave_packet = (struct request_s2s_leave *) packet;

    /* Log the received packet */
    fprintf(stdout, "%s %s recv S2S LEAVE %s\n",
	    server_addr, client_ip, leave_packet->req_channel);
    /* Assert the channel is subscribed to, return if not */
    if (!hm_get(r_table, leave_packet->req_channel, (void **)&servers))
	return;

    /* Check each subscribed server in the list */
    for (i = 0L; i < ll_size(servers); i++) {
	(void)ll_get(servers, i, (void **)&server);
	/* Server found, remove from subscription list */
	if (!strcmp(server->ip_addr, client_ip)) {
	    (void)ll_remove(servers, i, (void **)&server);
	    break;
	}
    }
    /* Server removes itself from channel sub-tree if leaf */
    (void)remove_server_leaf(leave_packet->req_channel);
}

/**
 * Server recieves an S2S say request. The message gets broadcasted to all/any
 * users listening on the channel. The request is also forwarded to all
 * connected/listening neighboring servers. If the server is a leaf in the
 * channel sub-tree, and no users are listening on the channel, the server replies
 * by sending an S2S leave request.
 */
static void server_s2s_say_request(const char *packet, char *client_ip) {

    Server *server, *sender;
    LinkedList *users, *servers;
    long i;
    struct request_s2s_leave leave_packet;
    struct request_s2s_say *say_packet = (struct request_s2s_say *) packet;

    /* Get the sending server */
    if (!hm_get(neighbors, client_ip, (void **)&sender))
	return;
    update_server_time(sender);
    /* Get list of listening servers */
    if (!hm_get(r_table, say_packet->req_channel, (void **)&servers))
	return;

    /* Initialize and set leave packet members */
    memset(&leave_packet, 0, sizeof(leave_packet));
    leave_packet.req_type = REQ_S2S_LEAVE;
    strncpy(leave_packet.req_channel, say_packet->req_channel, (CHANNEL_MAX - 1));

    /* Check the packet ID for uniqueness */
    if (!id_unique(say_packet->id)) {
	/* Reply to sender with S2S if duplicate, loop detected */
	sendto(socket_fd, &leave_packet, sizeof(leave_packet), 0,
		(struct sockaddr *)sender->addr, sizeof(*sender->addr));
	/* Log the sent leave packet */
	fprintf(stdout, "%s %s send S2S LEAVE %s\n",
		server_addr, sender->ip_addr, say_packet->req_channel);
	return;
    }
    queue_id(say_packet->id);	/* Add the packet to the ID queue */

    /* Log the received packet */
    fprintf(stdout, "%s %s recv S2S SAY %s %s \"%s\"\n", server_addr, client_ip,
	    say_packet->req_username, say_packet->req_channel, say_packet->req_text);

    /* Broadcast the message to all local users on channel */
    if (hm_get(channels, say_packet->req_channel, (void **)&users))
	(void)broadcast_message(users, say_packet->req_username,
				say_packet->req_channel, say_packet->req_text);

    /* Server is a leaf, remove it from sub-tree */
    if (remove_server_leaf(say_packet->req_channel))
	return;

    /* If server not a leaf, forward S2S request to all subscribed neighbors */
    for (i = 0L; i < ll_size(servers); i++) {
	(void)ll_get(servers, i, (void **)&server);
	if (!strcmp(server->ip_addr, sender->ip_addr))
	    continue;	/* Skip the server that sent the request */
	/* Forward the packet to the subscribed neighbor */
	sendto(socket_fd, say_packet, sizeof(*say_packet), 0,
		(struct sockaddr *)server->addr, sizeof(*server->addr));
	/* Log the sent packet */
	fprintf(stdout, "%s %s send S2S SAY %s %s \"%s\"\n",
		server_addr, server->ip_addr, say_packet->req_username,
		say_packet->req_channel, say_packet->req_text);
    }
}

/**
 * Server recieves a S2S LIST request. Server will collect all channel names it
 * has stored inside its table(s), and appends it to the packets collection. If
 * there are still servers to visit, the server forwards the S2S LIST to the next,
 * otherwise sends a reply back to the client.
 */
static void server_s2s_list_request(const char *packet, char *client_ip) {

    HashMap *ch_set = NULL, *ip_set = NULL;
    char **array = NULL;
    int unique, size;
    long i, j, len = 0L;
    struct sockaddr_in *client = NULL;
    struct text_list *list_packet = NULL;
    struct request_s2s_list *forward = NULL;
    struct request_s2s_list *s2s_list = (struct request_s2s_list *) packet;    

    /* Log the received packet */
    fprintf(stdout, "%s %s recv S2S LIST\n", server_addr, client_ip);
    
    /* Create hashmap to hold list, transfer from packet into map */
    if ((ch_set = hm_create(0L, 0.0f)) == NULL)
	goto free;
    for (i = 0; i < s2s_list->nchannels; i++)
	if (!hm_containsKey(ch_set, s2s_list->payload[i].element))
	    (void)hm_put(ch_set, s2s_list->payload[i].element, NULL, NULL);

    /* Only add the channels if ID not in cache; this is to prevent loops */
    if ((unique = id_unique(s2s_list->id)) != 0) {
	queue_id(s2s_list->id);
	/* Retrieve array of channel names */
	if ((array = hm_keyArray(channels, &len)) == NULL)
	    if (!hm_isEmpty(channels))
		goto free;
	/* Add all channels from array into map */
	for (i = 0L; i < len; i++)
	    if (!hm_containsKey(ch_set, array[i]))
		(void)hm_put(ch_set, array[i], NULL, NULL);
	free(array);
    }

    /* Get array of neighboring IPs, create new map for IPs to visit */
    if ((array = hm_keyArray(neighbors, &len)) == NULL)
	goto free;
    if ((ip_set = hm_create(0L, 0.0f)) == NULL)
	goto free;
    
    /* Add the neighboring IPs only if packet hasn't visited here */
    if (unique) {
	for (i = 0L; i < len; i++)
	    if (strcmp(array[i], client_ip))
		(void)hm_put(ip_set, array[i], NULL, NULL);
    }
    /* Transfer the rest of IPs from packet into map */
    j = i;
    for (i = 0; i < s2s_list->nto_visit; i++)
	(void)hm_put(ip_set, s2s_list->payload[j + i].element, NULL, NULL);
    free(array);

    /* If there are no more servers to visit, we can send response back to client */
    if (hm_isEmpty(ip_set)) {

	/* Get the client's IP address */
	if ((client = get_addr(s2s_list->client.ip_addr)) == NULL)
	    goto free;
	/* Retrieve array of collected channels */
	if ((array = hm_keyArray(ch_set, &len)) == NULL)
	    goto free;
	/* Calculate size of response packet, allocate memory */
	size = (sizeof(struct text_list) + (sizeof(struct channel_info) * len));
	if ((list_packet = (struct text_list *)malloc(size)) == NULL)
	    goto free;

	/* Initialize and set packet members */
	memset(list_packet, 0, sizeof(*list_packet));
	list_packet->txt_type = TXT_LIST;
	list_packet->txt_nchannels = (int)len;
	/* Copy all channels into the packet */
	for (i = 0L; i < len; i++)
	    strncpy(list_packet->txt_channels[i].ch_channel, array[i], (CHANNEL_MAX - 1));

	/* Send the packet to client, log the sent packet */
	sendto(socket_fd, list_packet, size, 0,
	    (struct sockaddr *)client, sizeof(*client));
	fprintf(stdout, "%s %s send LIST REPLY\n", server_addr, s2s_list->client.ip_addr);
	goto free;
    }

    /* Here, there are still servers to visit */
    /* Calculate size of packet, allocate the memory */
    size = (sizeof(struct request_s2s_list) +
	    ((sizeof(struct s2s_list_container) * 
	    (hm_size(ch_set) + hm_size(ip_set) - 1))));
    if ((forward = (struct request_s2s_list *)malloc(size)) == NULL)
	goto free;
    /* Initialize and set packet members */
    memset(forward, 0, sizeof(*forward));
    forward->req_type = REQ_S2S_LIST;
    forward->id = s2s_list->id;
    strncpy(forward->client.ip_addr, s2s_list->client.ip_addr, (IP_MAX - 1));
    /* Get array of channels, copy contents into packet */
    if ((array = hm_keyArray(ch_set, &len)) == NULL)
	goto free;
    forward->nchannels = (int)len;
    for (i = 0L; i < len; i++)
	strncpy(forward->payload[i].element, array[i], (CHANNEL_MAX - 1));
    free(array);
    
    /* Get array of IPs left to visit, copy contents into packet */
    if ((array = hm_keyArray(ip_set, &len)) == NULL)
	goto free;
    forward->nto_visit = (int)len - 1;
    j = i;
    for (i = 0L; i < len - 1; i++)
	strncpy(forward->payload[j + i].element, array[i + 1], (CHANNEL_MAX - 1));

    /* Get the address of next server to send to */
    if ((client = get_addr(array[0])) == NULL)
	goto free;
    /* Send the packet, log the sent packet */
    sendto(socket_fd, forward, size, 0, (struct sockaddr *)client, sizeof(*client));
    fprintf(stdout, "%s %s send S2S LIST\n", server_addr, array[0]);
    goto free;
    
free:
    /* Free all allocated memory */
    if (array != NULL) free(array);
    if (ch_set != NULL) hm_destroy(ch_set, NULL);
    if (ip_set != NULL) hm_destroy(ip_set, NULL);
    if (client != NULL) free(client);
    if (forward != NULL) free(forward);
    if (list_packet != NULL) free(list_packet);
    return;
}

/**
 * Server receives a S2S WHO request. Server will append the list of users that
 * are subscribed on the requested channel onto packet (if the channel exists in
 * the server's table(s)). If there are still servers to visit, the server forwards
 * the S2S request to the next server, otherwise it sends a reply back to the client.
 */
static void server_s2s_who_request(const char *packet, char *client_ip) {
    
    LinkedList *temp, *user_list = NULL;
    HashMap *ip_set = NULL;
    User **t_array = NULL;
    char **array = NULL;
    int unique, size;
    long i, j, len = 0L;
    struct sockaddr_in *client = NULL;
    struct text_who *who_packet = NULL;
    struct request_s2s_who *forward = NULL;
    struct request_s2s_who *s2s_who = (struct request_s2s_who *) packet;

    /* Log the received packet */
    fprintf(stdout, "%s %s recv S2S WHO %s\n", server_addr, client_ip, s2s_who->channel);

    /* Create new list to store usernames */
    if ((user_list = ll_create()) == NULL)
	goto free;
    /* Copy usernames from packet into list */
    for (i = 0; i < s2s_who->nusers; i++)
	(void)ll_add(user_list, strdup(s2s_who->payload[i].element));

    /* Only add usernames if not visited; this is to prevent loops */
    if ((unique = id_unique(s2s_who->id)) != 0) {
	queue_id(s2s_who->id);
	/* Get the array of usernames, only if channel exists */
	if (hm_containsKey(channels, s2s_who->channel))
	    hm_get(channels, s2s_who->channel, (void **)&temp);
	if ((t_array = (User **)ll_toArray(temp, &len)) == NULL)
	    goto free;
	/* Copy array contents into new list */
	for (i = 0L; i < len; i++)
	    (void)ll_add(user_list, strdup(t_array[i]->username));
	free(t_array);
    }

    /* Retrieve list of neighboring IPs to visit */
    if ((array = hm_keyArray(neighbors, &len)) == NULL)
	goto free;
    /* Create new hashmap to hold these IPs */
    if ((ip_set = hm_create(0L, 0.0f)) == NULL)
	goto free;
    /* Only add the neighboring IPs if not already visited */
    if (unique) {
	for (i = 0L; i < len; i++)
	    if (strcmp(array[i], client_ip))
		(void)hm_put(ip_set, array[i], NULL, NULL);
    }

    /* Copy the IP visitation list into the map */
    j = i;
    for (i = 0; i < s2s_who->nto_visit; i++)
	(void)hm_put(ip_set, s2s_who->payload[j + i].element, NULL, NULL);
    free(array);

    /* If there are IPs left, there are still servers to visit */
    if (hm_isEmpty(ip_set)) {
	
	/* Get address of client to send response to */
	if ((client = get_addr(s2s_who->client.ip_addr)) == NULL)
	    goto free;
	/* Get array of usernames to copy */
	if ((array = (char **)ll_toArray(user_list, &len)) == NULL)
	    goto free;
	/* Calculate the packet size, allocate the memory */
	size = (sizeof(struct text_who) + (sizeof(struct user_info) * len));
	if ((who_packet = (struct text_who *)malloc(size)) == NULL)
	    goto free;

	/* Initialize and set packet members */
	memset(who_packet, 0, sizeof(*who_packet));
	who_packet->txt_type = TXT_WHO;
	who_packet->txt_nusernames = (int)len;
	strncpy(who_packet->txt_channel, s2s_who->channel, (CHANNEL_MAX - 1));
	/* Copy usernames into response packet */
	for (i = 0L; i < len; i++)
	    strncpy(who_packet->txt_users[i].us_username, array[i], (USERNAME_MAX - 1));

	/* Send the packet to client, log the sent packet */
	sendto(socket_fd, who_packet, size, 0, (struct sockaddr *)client, sizeof(*client));
	fprintf(stdout, "%s %s send WHO REPLY %s\n",
		server_addr, s2s_who->client.ip_addr, who_packet->txt_channel);
	goto free;
    }

    /* Here, there are still servers left to visit */
    /* Calculate the packet size, allocate the memory */
    size = (sizeof(struct request_s2s_who) +
	    ((sizeof(struct s2s_who_container) * 
	    ll_size(user_list) + (hm_size(ip_set) - 1))));
    if ((forward = (struct request_s2s_who *)malloc(size)) == NULL)
	goto free;
    
    /* Initialize and set packet members */
    memset(forward, 0, sizeof(*forward));
    forward->req_type = REQ_S2S_WHO;
    forward->id = s2s_who->id;
    strncpy(forward->client.ip_addr, s2s_who->client.ip_addr, (IP_MAX - 1));
    strncpy(forward->channel, s2s_who->channel, (CHANNEL_MAX - 1));

    /* Get array of usernames, copy contents into packet */
    if ((array = (char **)ll_toArray(user_list, &len)) == NULL)
	goto free;
    forward->nusers = (int)len;
    for (i = 0L; i < len; i++)
	strncpy(forward->payload[i].element, array[i], (USERNAME_MAX - 1));
    free(array);
    
    /* Get array of IPs to visit, copy contents into packet */
    if ((array = hm_keyArray(ip_set, &len)) == NULL)
	goto free;
    forward->nto_visit = (int)len - 1;
    j = i;
    for (i = 0L; i < len - 1; i++)
	strncpy(forward->payload[j + i].element, array[i + 1], (USERNAME_MAX - 1));

    /* Get address of next server to send to */
    if ((client = get_addr(array[0])) == NULL)
	goto free;
    /* Send the packet, log the sent packet */
    sendto(socket_fd, forward, size, 0, (struct sockaddr *)client, sizeof(*client));
    fprintf(stdout, "%s %s send S2S WHO %s\n", server_addr, array[0], forward->channel);
    goto free;
   
free:
    /* Free all allocated memory */
    if (t_array != NULL) free(t_array);
    if (array != NULL) free(array);
    if (user_list != NULL) ll_destroy(user_list, free);
    if (ip_set != NULL) hm_destroy(ip_set, NULL);
    if (client != NULL) free(client);
    if (forward != NULL) free(forward);
    if (who_packet != NULL) free(who_packet);
    return;
}

/**
 * Frees the reserved memory occupied by the specified LinkedList. Used by
 * the LinkedList destructor.
 */
static void free_ll(LinkedList *ll) {
    
    if (ll != NULL)
	ll_destroy(ll, NULL);
}

/**
 * Cleans up after the server before shutting down by freeing and returning all
 * reserved memory back to the heap; this includes destroying the hashmaps of the
 * users and channels, any other datastructures used within them, and closing any
 * open sockets.
 */
static void cleanup(void) {
    
    /* Close the socket if open */
    if (socket_fd != -1)
	close(socket_fd);
    /* Destroy the hashmap holding the channels */
    if (channels != NULL)
	hm_destroy(channels, (void *)free_ll);
    /* Destroy the hashmap containing all logged in users */
    if (users != NULL)
	hm_destroy(users, (void *)free_user);
    /* Destroy the hashmap of channels neighboring servers are listening to */
    if (r_table != NULL)
	hm_destroy(r_table, (void *)free_ll);
    /* Destroy the hashmap containing neighboring servers */
    if (neighbors != NULL)
	hm_destroy(neighbors, (void *)free_server);
}

/**
 * Prints the specified message to standard error stream as a program error
 * message, then terminates the server application.
 */
static void print_error(const char *msg) {
    
    fprintf(stderr, "[Server]: %s\n", msg);
    exit(0);
}

/**
 * Function that handles an interrupt signal from the user. Simply exits
 * the program, which will invoke the cleanup method registered with the
 * atexit() function.
 */
static void server_exit(UNUSED int signo) {
    
    fprintf(stdout, "%s Duckchat server terminated\n", server_addr);
    exit(0);
}

/**
 * Runs the Duckchat server.
 */
int main(int argc, char *argv[]) {

    struct sockaddr_in server, client;
    struct hostent *host_end;
    struct timeval timeout;
    socklen_t addr_len = sizeof(client);
    fd_set receiver;
    int i, port_num, res, mode;
    char buffer[BUFF_SIZE], client_ip[128];

    /* Assert that the correct number of arguments were given */
    /* Print program usage otherwise */
    if (argc < 3 || argc % 2 != 1) {
	fprintf(stdout, "Usage: %s domain_name port_number [domain_name port_number] ...\n", argv[0]);
	fprintf(stdout, "  The first two arguments are the IP address and port number this server binds to.\n");
	fprintf(stdout, "  The following optional arguments are the IP address and port number of adjacent server(s) to connect to.\n");
	return 0;
    }

    /* Register function to cleanup when user stops the server */
    /* Also register the cleanup() function to be invoked upon program termination */
    if ((signal(SIGINT, server_exit)) == SIG_ERR)
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
    if ((host_end = gethostbyname(argv[1])) == NULL) {
	sprintf(buffer, "Failed to locate the host.");
	print_error(buffer);
    }

    /* Create server address struct, set internet family, address, & port number */
    memset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    memcpy((char *)&server.sin_addr, (char *)host_end->h_addr_list[0], host_end->h_length);
    server.sin_port = htons(port_num);

    /* Create the UDP socket, bind name to socket */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to create a socket for the server.");
    if (bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
	sprintf(buffer, "Failed to assign the requested address.");
	print_error(buffer);
    }

    /* Create & initialize data structures for server to use */
    if ((users = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    if ((channels = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    LinkedList *default_ll;
    if ((default_ll = ll_create()) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    if (!hm_put(channels, DEFAULT_CHANNEL, default_ll, NULL))
	print_error("Failed to allocate a sufficient amount of memory.");
    if ((neighbors = hm_create(20L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    if ((r_table = hm_create(100L, 0.0f)) == NULL)
	print_error("Failed to allocate a sufficient amount of memory.");
    /* Allocate memory for neighboring servers */
    argc -= 3; argv += 3;   /* Skip to neighboring server arg(s) */
    if (!add_neighbors(argv, argc))
	print_error("Failed to allocate a sufficient amount of memory.");

    /* Initialize message ID queue */
    for (i = 0; i < MSGQ_SIZE; i++)
	id_cache[i] = 0L;

    /* Display successful launch title & address */
    sprintf(server_addr, "%s:%d", inet_ntoa(server.sin_addr), ntohs(server.sin_port));
    fprintf(stdout, "%s Duckchat server launched\n", server_addr);
    /* Set the timeout timer for select() */
    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = 60;
    mode = 0;

    /**
     * Main application loop; a packet is received from one of the connected
     * clients, and the packet is dealt with accordingly.
     */
    while (1) {

	/* Watch the socket for packets from connected clients */
	FD_ZERO(&receiver);
	FD_SET(socket_fd, &receiver);
	res = select((socket_fd + 1), &receiver, NULL, NULL, &timeout);

	/* A minute passes, flood all servers with JOIN requests */
	if (res == 0) {
	    refresh_s2s_joins();
	    mode++;
	    /* Checks for inactive users and servers */
	    if (mode >= REFRESH_RATE) {
		logout_inactive_users();
		remove_inactive_servers();
		mode = 0;
	    }
	    /* Reset timer and continue */
	    timeout.tv_sec = 60;
	    continue;
	}
    
	/* Receive a packet from a connected client */
	memset(buffer, 0, sizeof(buffer));
	if (recvfrom(socket_fd, buffer, sizeof(buffer), 0,
		(struct sockaddr *)&client, &addr_len) < 0) continue;
	/* Extract full address of sender, parse packet */
	sprintf(client_ip, "%s:%d", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
	struct text *packet_type = (struct text *) buffer;

	/* Examine the packet type received */
	switch (packet_type->txt_type) {
	    case REQ_VERIFY:
		/* Check to see if the username is taken */
		server_verify_request(buffer, client_ip, &client);
		break;
	    case REQ_LOGIN:
		/* A client requests to login to the server */
		server_login_request(buffer, client_ip, &client);
		break;
	    case REQ_LOGOUT:
		/* A client requests to logout from the server */
		server_logout_request(client_ip);
		break;
	    case REQ_JOIN:
		/* A client requests to join a channel */
		server_join_request(buffer, client_ip);
		break;
	    case REQ_LEAVE:
		/* A client requests to leave a channel */
		server_leave_request(buffer, client_ip);
		break;
	    case REQ_SAY:
		/* A client sent a message to broadcast in their active channel */
		server_say_request(buffer, client_ip);
		break;
	    case REQ_LIST:
		/* A client requests a list of all the channels on the server */
		server_list_request(client_ip);
		break;
	    case REQ_WHO:
		/* A client requests a list of users on the specified channel */
		server_who_request(buffer, client_ip);
		break;
	    case REQ_KEEP_ALIVE:
		/* Received from an inactive user, keeps them logged in */
		server_keep_alive_request(client_ip);
		break;
	    case REQ_S2S_VERIFY:
		/* Server-to-server verify request, check for username verification */
		server_s2s_verify(buffer, client_ip);
		break;
	    case REQ_S2S_JOIN:
		/* Server-to-server join request, forward it to neighbors */
		server_s2s_join_request(buffer, client_ip);
		break;
	    case REQ_S2S_LEAVE:
		/* Server-to-server leave request, unsubscribe server from a channel */
		server_s2s_leave_request(buffer, client_ip);
		break;
	    case REQ_S2S_SAY:
		/* Server-to-server say request, forward to all subscribed servers */
		server_s2s_say_request(buffer, client_ip);
		break;
	    case REQ_S2S_LIST:
		/* Server-to-server list request, collect channel names and forward to neighbors */
		server_s2s_list_request(buffer, client_ip);
		break;
	    case REQ_S2S_WHO:
		/* Server-to-server who request, collect listening users and forward to neighbors */
		server_s2s_who_request(buffer, client_ip);
		break;
	    default:
		/* Do nothing, likey a bogus packet */
		break;
	}
    }

    return 0;
}
