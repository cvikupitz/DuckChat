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
#include <unistd.h>
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

/// FIXME - Ensure byte order, htonl/s()....


/* Suppress compiler warnings for unused parameters */
#define UNUSED __attribute__((unused))
/* Maximum buffer size for messages and packets */
#define BUFF_SIZE 20000
/* The default channel for the user to join upon logging in */
/* This channel will also never be removed, even when empty */
#define DEFAULT_CHANNEL "Common"
/* Refresh rate (in minutes) of the server to scan for and logout inactive users */
#define REFRESH_RATE 2


/* Socket address for the server */
static struct sockaddr_in server;
/* File descriptor for the socket to use */
static int socket_fd = -1;
/* Time variables/structs used for logging the current time */
struct tm *timestamp;
time_t timer;
/* HashMap of all users currently logged on */
/* Maps the user's IP address in a string to the user struct */
static HashMap *users = NULL;
/* HashMap of all the channels currently available */
/* Maps the channel name to a linked list of pointers of all users on the channel */
static HashMap *channels = NULL;


/**
 * A structure to represent a user logged into the server.
 */
typedef struct {
    struct sockaddr_in *addr;	/* The client's address to send packets to */
    socklen_t len;		/* The length of the client's address */
    LinkedList *channels;	/* List of channel names user is listening to */
    char *ip_addr;		/* Full IP address of client in string format */
    char *username;		/* The username of user */
    int min_last;		/* Clock minute of last received packet from this client */
} User;

/**
 * Creates a new instance of a user logged in the server by allocating memory and returns
 * a pointer to the new user instance. The user is created given an IP address in a string,
 * the username, and the addressing information to send packets to. Returns pointer to new
 * user instance if creation successful, or NULL if not (malloc() error).
 */
static User *malloc_user(const char *ip, const char *name, struct sockaddr_in *addr, socklen_t len) {

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
	new_user->len = len;
	strcpy(new_user->ip_addr, ip);
	strcpy(new_user->username, name);
	time(&timer);
	timestamp = localtime(&timer);
	new_user->min_last = timestamp->tm_min;
    }

    return new_user;    
}

/**
 * FIXME
 */
static void update_user_time(User *user) {
    if (user != NULL) {
	time(&timer);
	timestamp = localtime(&timer);
	user->min_last = timestamp->tm_min;
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
 * Prints out the specified message for the server log. Prints out the full current
 * date and time followed by the message.
 */
static void print_log_message(const char *msg) {

    /* Access the current local time */
    time(&timer);
    timestamp = localtime(&timer);
    /* Prints out the logging date, time, & the message */
    fprintf(stdout, "[%02d/%02d/%d %02d:%02d] %s\n", (timestamp->tm_mon + 1),
		    timestamp->tm_mday, (1900 + timestamp->tm_year),
		    timestamp->tm_hour, timestamp->tm_min, msg);
}

/**
 * Sends a packet containing the error message 'msg' to the client with the specified
 * address information. Also logs the packet sent to the address with the error
 * message.
 */
static void server_send_error(struct sockaddr_in *addr, socklen_t len, const char *msg) {
    
    struct text_error error_packet;
    char buffer[256];

    /* Initialize the error packet; set the type */
    memset(&error_packet, 0, sizeof(error_packet));
    error_packet.txt_type = TXT_ERROR;
    /* Copy the error message into packet, ensure length does not exceed limit allowed */
    strncpy(error_packet.txt_error, msg, (SAY_MAX - 1));
    /* Send packet off to user */
    sendto(socket_fd, &error_packet, sizeof(error_packet), 0,
		(struct sockaddr *)addr, len);
    /* Log the sent error message */
    sprintf(buffer, "*** Sent error message to %s:%d -> \"%s\"",
		inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), msg);
    print_log_message(buffer);
}

/**
 * Server receives a login packet; the server allocates memory and creates an instance of the
 * new user and connects them to the server.
 */
static void server_login_request(const char *packet, char *client_ip, struct sockaddr_in *addr, socklen_t len) {

    User *user;
    char name[USERNAME_MAX], buffer[256];
    struct request_login *login_packet = (struct request_login *) packet;

    /* Copy username into buffer, ensures name length does not exceed max allowed */
    memset(name, 0, sizeof(name));
    strncpy(name, login_packet->req_username, (USERNAME_MAX - 1));

    /* Create a new instance of the user */
    /* Send error back to client if malloc() failed, log the error */
    if ((user = malloc_user(client_ip, name, addr, len)) == NULL) {
	server_send_error(addr, len, "Error: Failed to log into the server");
	sprintf(buffer, "%s failed to login: unable to allocate a sufficient amount of memory",
			client_ip);
	print_log_message(buffer);
	return;
    }

    /* Add the new user into the users hashmap */
    /* Send error back to client if failed, log the error */
    if (!hm_put(users, client_ip, user, NULL)) {
	server_send_error(addr, len, "Error: Failed to log into the server.");
	sprintf(buffer, "%s failed to login: unable to allocate a sufficient amount of memory.",
			client_ip);
	print_log_message(buffer);
	free(user);
	return;
    }

    /* Log the user login information */
    sprintf(buffer, "%s logged in from %s", user->username, user->ip_addr);
    print_log_message(buffer);
}

/**
 * Server receives a join packet; the server adds the client to the requested channel, so
 * that they can now receive messages from other subscribed clients.
 */
static void server_join_request(const char *packet, char *client_ip) {
    
    User *user, *tmp;
    LinkedList *user_list;
    int ch_len;
    long i;
    char *joined;
    char buffer[256];
    struct request_join *join_packet = (struct request_join *) packet;

    /* Assert that the user is currently logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    update_user_time(user);

    /* Set the channel name length; shorten it down if exceeds max length allowed */
    ch_len = ((strlen(join_packet->req_channel) > (CHANNEL_MAX - 1)) ?
				(CHANNEL_MAX - 1) : strlen(join_packet->req_channel));
    /* Allocate memory from heap for name, report and log error if failed */
    if ((joined = (char *)malloc(ch_len + 1)) == NULL) {
	sprintf(buffer, "Error: Failed to join %s", join_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	return;
    }

    /* Extract the channel name from packet */
    memcpy(joined, join_packet->req_channel, ch_len);
    joined[ch_len] = '\0';
    /* Add the channel to user's subscribed list, send error if failed, log error */
    if (!ll_add(user->channels, joined)) {
	sprintf(buffer, "Error: Failed to join %s", joined);
	server_send_error(user->addr, user->len, buffer);
	free(joined);
	return;
    }

    /* User has joined a channel that already exists */
    if (!hm_get(channels, joined, (void **)&user_list)) {

	/* Create the new channel list, send error back if failed, log the error */
	if ((user_list = ll_create()) == NULL) {
	    sprintf(buffer, "Error: Failed to join %s", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
	/* Add the user to the list, send error back if failed, log the error */
	if (!ll_add(user_list, user)) {
	    ll_destroy(user_list, NULL);
	    sprintf(buffer, "Error: Failed to join %s", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
	/* Add the channel to the server's channel collection */
	/* Send error back to client if failed, log the error */
	if (!hm_put(channels, joined, user_list, NULL)) {
	    ll_destroy(user_list, NULL);
	    sprintf(buffer, "Error: Failed to join %s", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
	/* Creation and insertion(s) of channel successful, log the event */
	sprintf(buffer, "%s created the channel %s", user->username, joined);
	print_log_message(buffer);

    /* User has joined a channel that does not exist */
    } else {
	
	/* Check to see if user is already subscribed; makes sure not to add duplicate instance(s) */
	for (i = 0L; i < ll_size(user_list); i++) {
	    (void)ll_get(user_list, i, (void **)&tmp);
	    if (strcmp(user->ip_addr, tmp->ip_addr) == 0) {
		/* User found, log the join event and return */
		sprintf(buffer, "%s joined the channel %s", user->username, joined);
		print_log_message(buffer);
		return;
	    }
	}

	/* User was not found, so add them to subscription list */
	/* If failed, send error back to client, log the error */
	if (!ll_add(user_list, user)) {
	    sprintf(buffer, "Error: Failed to join %s", join_packet->req_channel);
	    server_send_error(user->addr, user->len, buffer);
	    return;
	}
    }

    /* Log the join event */
    sprintf(buffer, "%s joined the channel %s", user->username, joined);
    print_log_message(buffer);
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
	sprintf(buffer, "No channel by the name %s", leave_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "%s attempted to leave non-existent channel %s", user->username, leave_packet->req_channel);
	print_log_message(buffer);
	return;
    }

    /* Next, remove the requested channel from the user's list of subscribed channels */
    for (i = 0L; i < ll_size(user->channels); i++) {
	(void)ll_get(user->channels, i, (void **)&ch);
	if (strcmp(channel, ch) == 0) {
	    /* Channel found, remove it from list and free reserved memory */
	    ll_remove(user->channels, i, (void **)&ch);
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

    if (removed) {
	/* User was successfully removed, log the event */
	sprintf(buffer, "%s left the channel %s", user->username, channel);
	print_log_message(buffer);
    } else {
	/* User was not removed, wasn't subscribed to channel to begin with */
	/* Send a message back to user notifying them, log the error */
	sprintf(buffer, "You are not subscribed to %s", channel);
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "%s attempted to leave a channel they are not subscribed to", user->username);
	print_log_message(buffer);
	return;
    }

    /* If the channel the user left becomes empty, remove it from channel list */
    if (ll_isEmpty(user_list) && strcmp(channel, DEFAULT_CHANNEL)) {
	/* Free all memory reserved by deleted channel */
	(void)hm_remove(channels, channel, (void **)&user_list);
	ll_destroy(user_list, NULL);
	/* Log the channel deletion */
	sprintf(buffer, "Removed the empty channel %s", channel);
	print_log_message(buffer);
    }
}

/**
 * Server receiveds a say packet from a client; the server broadcasts the message
 * back to all connected clients subscribed to the requested channel by sending
 * a packet to each of the subscribed clients.
 */
static void server_say_request(const char *packet, char *client_ip) {
    
    User *user;
    User **listeners;
    LinkedList *ch_users;
    long i, len;
    char buffer[256];
    struct request_say *say_packet = (struct request_say *) packet;
    struct text_say msg_packet;

    /* Assert user is logged in; do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    /* Assert that the channel exists; do nothing if not */
    if (!hm_get(channels, say_packet->req_channel, (void **)&ch_users))
	return;
    update_user_time(user);

    /* Get the list of users listening to the channel */
    /* Respond to user with error message if malloc() failure, log the error */
    if ((listeners = (User **)ll_toArray(ch_users, &len)) == NULL) {
	sprintf(buffer, "Error: Failed to send the message");
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "Failed to send a message from %s to channel %s",
		    user->username, say_packet->req_channel);
	print_log_message(buffer);
	return;
    }

    /* Initialize the SAY packet to send; set the type, channel, and username */
    memset(&msg_packet, 0, sizeof(msg_packet));
    strncpy(msg_packet.txt_channel, say_packet->req_channel, (CHANNEL_MAX - 1));
    strncpy(msg_packet.txt_username, user->username, (USERNAME_MAX - 1));
    strncpy(msg_packet.txt_text, say_packet->req_text, (SAY_MAX - 1));

    /* Send the packet to each user listening on the channel */
    for (i = 0L; i < len; i++)
	sendto(socket_fd, &msg_packet, sizeof(msg_packet), 0,
		(struct sockaddr *)listeners[i]->addr, listeners[i]->len);
    /* Log the message */
    sprintf(buffer, "[%s][%s] -> \"%s\"", msg_packet.txt_channel,
		user->username, msg_packet.txt_text);
    print_log_message(buffer);
    /* Free the array */
    free(listeners);
}

/**
 * Server receives a list packet from a client; the server compiles a list of
 * all the channels currently available on the server, then sends the packet
 * back to the client.
 */
static void server_list_request(char *client_ip) {

    User *user;
    int size;
    long i, len;
    char **ch_list;
    char buffer[256];
    struct text_list *list_packet;

    /* Assert that the user is logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    update_user_time(user);

    /* Retrieve the complete list of channel names */
    /* Send error message back to client if failed (malloc() error), log the error */
    if ((ch_list = hm_keyArray(channels, &len)) == NULL) {
	server_send_error(user->addr, user->len, "Error: Failed to list the channels");
	sprintf(buffer, "Failed to list channels for user %s", user->username);
	print_log_message(buffer);
	return;
    }

    /* Calculate the exact size of packet to send back */
    size = sizeof(struct text_list) + (sizeof(struct channel_info) * len);
    /* Allocate memory for the packet using calculated size */
    /* Send error back to user if failed (malloc() error), log the error */
    if ((list_packet = malloc(size)) == NULL) {
	server_send_error(user->addr, user->len, "Error: Failed to list the channels");
	sprintf(buffer, "Failed to list channels for user %s", user->username);
	print_log_message(buffer);
	free(ch_list);
	return;
    }

    /* Initialize the packet; set the type and number of channels */
    memset(list_packet, 0, size);
    list_packet->txt_type = TXT_LIST;
    list_packet->txt_nchannels = (int)len;
    /* Copy each channel name from the list into the packet */
    for (i = 0L; i < len; i++)
	strncpy(list_packet->txt_channels[i].ch_channel, ch_list[i], (CHANNEL_MAX - 1));

    /* Send the packet to client, log the listing event */
    sendto(socket_fd, list_packet, size, 0,
		(struct sockaddr *)user->addr, user->len);
    sprintf(buffer, "%s listed available channels on server", user->username);
    print_log_message(buffer);

    /* Return all allocated memory back to heap */
    free(ch_list);
    free(list_packet);
}

/**
 * Server receives a who packet from a client; the server compiles a list of all
 * the users currently subscribed to the requested channel, then sends the packet
 * back to the client.
 */
static void server_who_request(const char *packet, char *client_ip) {

    User *user, **user_list;
    LinkedList *subscribers;
    int size;
    long i, len;
    char buffer[256];
    struct text_who *send_packet;
    struct request_who *who_packet = (struct request_who *) packet;

    /* Assert that the user is logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    update_user_time(user);

    /* Assert that the channel requested exists, send error back if it doesn't, log the error */
    if (!hm_get(channels, who_packet->req_channel, (void **)&subscribers)) {
	sprintf(buffer, "No channel by the name %s", who_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "%s attempted to list users on non-existent channel %s",
		    user->username, who_packet->req_channel);
	print_log_message(buffer);
	return;
    }

    /* Check to see if channel is empty, send message to cient if so */
    /* Should not happen for any channel other than the default channel */
    if (ll_isEmpty(subscribers)) {
	sprintf(buffer, "The channel %s is currently empty", who_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "%s listed all users on channel %s", user->username, who_packet->req_channel);
	print_log_message(buffer);
	return;
    }

    /* Retrieve the list of users subscribed to the requested channel */
    /* Send error message back to client if failed (malloc() error), log the error */
    if ((user_list = (User **)ll_toArray(subscribers, &len)) == NULL) {
	sprintf(buffer, "Error: Failed to list users on %s", who_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "Failed to list users on channel %s for user %s",
		    who_packet->req_channel, user->username);
	print_log_message(buffer);
	return;    
    }

    /* Calculate the exact size of packet to send back */
    size = sizeof(struct text_who) + (sizeof(struct user_info) * len);
    /* Allocate memory for the packet using calculated size */
    /* Send error back to user if failed (malloc() error), log the error */
    if ((send_packet = malloc(size)) == NULL) {
	sprintf(buffer, "Error: Failed to list users on %s", who_packet->req_channel);
	server_send_error(user->addr, user->len, buffer);
	sprintf(buffer, "Failed to list users on channel %s for user %s",
		    who_packet->req_channel, user->username);
	print_log_message(buffer);
	free(user_list);
	return;
    }

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
		(struct sockaddr *)user->addr, user->len);
    sprintf(buffer, "%s listed all users on channel %s", user->username, who_packet->req_channel);
    print_log_message(buffer);

    /* Return all allocated memory back to heap */
    free(user_list);
    free(send_packet);
}

/**
 * Server receives a keep-alive packet from a client; the server simply updates the
 * user's last sent packet time so that they are not logged out due to inactivity.
 */
static void server_keep_alive_request(char *client_ip) {

    User *user;
    char buffer[256];

    /* Assert that the user is logged in, do nothing if not */
    if (!hm_get(users, client_ip, (void **)&user))
	return;
    update_user_time(user);
    
    /* Log the keep alive message received */
    sprintf(buffer, "%s kept alive", user->username);
    print_log_message(buffer);
}

/**
 * FIXME
 */
static void logout_user(User *user) {

    User *tmp;
    LinkedList *user_list;
    long i;
    char *ch;
    char buffer[256];

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
	    /* Log the channel deletion */
	    sprintf(buffer, "Removed the empty channel %s", ch);
	    print_log_message(buffer);
	}
	free(ch);   /* Free allocated memory  */
    }
    free_user(user);	/* Free allocated memory */
}

/**
 * Server receives a logout packet from a client; server removes the user from the
 * user database and any instances of them from all the channels.
 */
static void server_logout_request(char *client_ip) {

    User *user;
    char buffer[256];

    /* Assert the user is logged in, do nothing if not */
    if (!hm_remove(users, client_ip, (void **)&user))
	return;

    /* Log the user out, log the logout event */ 
    sprintf(buffer, "%s logged out", user->username);
    print_log_message(buffer);
    logout_user(user);
}

/**
 * FIXME
 */
static int user_inactive(User *user) {

    int diff;

    time(&timer);
    timestamp = localtime(&timer);
    if (timestamp->tm_min >= user->min_last)
	diff = (timestamp->tm_min - user->min_last);
    else
	diff = ((60 - user->min_last) + timestamp->tm_min);

    return (diff > REFRESH_RATE);
}

/**
 * FIXME
 */
static void logout_inactive_users(void) {
    
    User *user;
    long i, len;
    char **user_list;
    char buffer[256];

    if ((user_list = hm_keyArray(users, &len)) == NULL) {
	print_log_message("*** Failed to perform server scan, malloc() error");
	return;
    }

    print_log_message("Scanning server for inactive users...");
    for (i = 0L; i < len; i++) {
	if (!hm_get(users, user_list[i], (void **)&user))
	    continue;
	if (user_inactive(user)) {
	    sprintf(buffer, "Forcefully logged out inactive user %s", user->username);
	    print_log_message(buffer);
	    (void)hm_remove(users, user->ip_addr, (void **)&user);
	    logout_user(user);
	}
    }

    print_log_message("Scan complete");
    free(user_list);
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
 * Function that handles an interrupt signal from the user. Simply exits
 * the program, which will invoke the cleanup method registered with the
 * atexit() function.
 */
static void sig_handler(UNUSED int signo) {
    
    fprintf(stdout, "\n\nShutting down server...\n\n");
    exit(0);
}

/**
 * Runs the Duckchat server.
 */
int main(int argc, char *argv[]) {

    struct sockaddr_in client;
    struct hostent *host_end;
    struct timeval timeout;
    socklen_t addr_len = sizeof(client);
    fd_set receiver;
    int port_num, res;
    char buffer[BUFF_SIZE], client_ip[128];

    /* Assert that the correct number of arguments were given */
    /* Print program usage otherwise */
    if (argc != 3) {
	fprintf(stdout, "Usage: %s domain_name port_num\n", argv[0]);
	return 0;
    }

    /* Register function to cleanup when user stops the server */
    /* Also register the cleanup() function to be invoked upon program termination */
    if ((signal(SIGINT, sig_handler)) == SIG_ERR)
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
    memcpy((char *)&server.sin_addr.s_addr, (char *)host_end->h_addr, host_end->h_length);
    server.sin_port = htons(port_num);

    /* Create the UDP socket, bind name to socket */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to create a socket for the server.");
    if (bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
	print_error("Failed to assign the requested address.");

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

    /* Display successful launch title, timestamp & address */
    time(&timer);
    fprintf(stdout, "------ Launched DuckChat server ~ %s", ctime(&timer)); 
    fprintf(stdout, "------ Server assigned to address %s:%d\n",
		inet_ntoa(server.sin_addr), ntohs(server.sin_port));
    /* Set the timeout timer for select() */
    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = (REFRESH_RATE * 60);

    /**
     * Main application loop; a packet is received from one of the connected
     * clients, and the packet is dealt with accordingly.
     */
    while (1) {

	/* FIXME */
	FD_ZERO(&receiver);
	FD_SET(socket_fd, &receiver);
	res = select((socket_fd + 1), &receiver, NULL, NULL, &timeout);

	/* FIXME */
	if (res == 0) {
	    logout_inactive_users();
	    timeout.tv_sec = (REFRESH_RATE * 60);
	    continue;
	}
    
	/* Wait & receive a packet from a connected client */
	memset(buffer, 0, sizeof(buffer));
	if (recvfrom(socket_fd, buffer, sizeof(buffer), 0,
		(struct sockaddr *)&client, &addr_len) < 0) continue;
	/* Extract full address of sender, parse packet */
	sprintf(client_ip, "%s:%d", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
	struct text *packet_type = (struct text *) buffer;

	/* Examine the packet type received */
	switch (packet_type->txt_type) {
	    case REQ_LOGIN:
		/* A client requests to login to the server */
		server_login_request(buffer, client_ip, &client, addr_len);
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
	    default:
		/* Do nothing, likey a bogus packet */
		break;
	}
    }

    return 0;
}
