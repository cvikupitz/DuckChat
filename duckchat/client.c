/**
 * client.c
 * Author: Cole Vikupitz
 * Last Modified: 11/29/2017
 *
 * Client side of a chat application using the DuckChat protocol. The client sends
 * and receives packets from a server using this protocol and handles each of the
 * packets accordingly.
 *
 * Usage: ./client server_socket server_port username
 *
 * Resources Used:
 * Lots of help about basic socket programming received from Beej's Guide to Socket Programming:
 * https://beej.us/guide/bgnet/output/html/multipage/index.html
 */

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "duckchat.h"
#include "properties.h"
#include "raw.h"


/* Socket address for the server */
static struct sockaddr_in server;
/* The username of the client */
static char username[USERNAME_MAX];
/* The client's currently active channel */
static char active_channel[CHANNEL_MAX];
/* List of channels the client is currently subscribed/listening to */
static char subscribed[MAX_CHANNELS][CHANNEL_MAX];
/* File descriptor for the client's socket */
static int socket_fd = -1;


/**
 * Subscribes the client to the specified channel and the new channel becomes
 * the client's currently active channel. Returns 1 if successfully joined, or
 * 0 if not (client is subscribed to maximum number of channels allowed).
 */
static int join_channel(const char *channel) {
    
    int i;
    /* Search the subscription list to see if client is already subscribed */
    /* If client is already subscribed, switch it to active channel */
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], channel) == 0) {
	    strncpy(active_channel, subscribed[i], (CHANNEL_MAX - 1));
	    return 1;
	}
    }

    /* If client not subscribed, search for empty spot in subscription list */
    /* Add channel if list is not full and return 1, return 0 if list is full */
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], "") == 0) {
	    strncpy(subscribed[i], channel, (CHANNEL_MAX - 1));
	    strncpy(active_channel, channel, (CHANNEL_MAX - 1));
	    return 1;
	}
    }
    return 0;
}

/**
 * Removes the specified channel from the client's subscription list. If the
 * client's active channel is the channel being unsubscribed, the active
 * channel becomes dead (client has no active channel).
 */
static void leave_channel(const char *channel) {
    
    int i;
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], channel) == 0) {
	    strcpy(subscribed[i], "");
	    /* Check to see if active channel is the one to be left */
	    if (strcmp(active_channel, channel) == 0)
		strcpy(active_channel, "");
	    return;
	}
    }
}

/**
 * FIXME
 */
static void authenticate_client() {
    
}

/**
 * Sends a packet to the server requesting the client to join a channel.
 * Invoked when the user enters the command '/join <name>'. The channel
 * is added to the user's subscription list, only if the client is not
 * subscribed to the maximum number of channels allowed. Otherwise, the
 * channel is added and becomes the client's active channel.
 */
static void client_join_request(const char *request) {
    
    /* Parse the request, return with error if failed */
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    /* Attempt to add channel to subscription list */
    /* Return with error if subscription list is currently full */
    ++channel;	/* Skip leading whitespace character */
    if (!join_channel(channel)) {
	fprintf(stdout, "Cannot join channel, subscribed to the maximum allowed (%d).\n",
		MAX_CHANNELS);
	return;
    }
    /* Create & send the join channel packet to the server */
    struct request_join join_packet;
    memset(&join_packet, 0, sizeof(join_packet));
    join_packet.req_type = REQ_JOIN;
    strncpy(join_packet.req_channel, channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Sends a packet to the server requesting the client to leave the specified
 * channel. Invoked when the user enters the command '/leave <name>'. The
 * channel is removed from the user's local subscription list.
 */
static void client_leave_request(const char *request) {
    
    /* Parse the request, return with error if failed */
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    /* Removes the channel from the subscription list */
    ++channel;	/* Skip leading whitespace character */
    leave_channel(channel);
    /* Create & send the leave packet to the server */
    struct request_leave leave_packet;
    memset(&leave_packet, 0, sizeof(leave_packet));
    leave_packet.req_type = REQ_LEAVE;
    strncpy(leave_packet.req_channel, channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &leave_packet, sizeof(leave_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Sends a packet to the server requesting the server to distribute the
 * client's message. The client will receive the message on their prompt,
 * and the server is responsible for sending the packets to all other
 * clients currently on the client's active channel. If the user is not on
 * an active channel, no message should be sent.
 */
static void client_say_request(const char *request) {
    
    /* User is not active in a channel, do nothing */
    if (strcmp(active_channel, "") == 0)
	return;
    /* Create & send the say packet to the server */
    /* Packet should contain the message and active channel */
    struct request_say say_packet;
    memset(&say_packet, 0, sizeof(say_packet));
    say_packet.req_type = REQ_SAY;
    strncpy(say_packet.req_channel, active_channel, (CHANNEL_MAX - 1));
    strncpy(say_packet.req_text, request, (SAY_MAX - 1));
    sendto(socket_fd, &say_packet, sizeof(say_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Prints out a message to the user, including the user who sent the
 * message, their active channel, and the message itself. Extracted
 * from the packet that is received from the server.
 */
static void server_say_reply(const char *packet) {
    
    struct text_say *say_packet = (struct text_say *) packet;
    fprintf(stdout, "[%s][%s]: %s\n", say_packet->txt_channel,
		    say_packet->txt_username, say_packet->txt_text);
}

/**
 * Sends a packet to the server requesting the server to return a
 * list of available channels to the client. Invoked when the user
 * enters the special command '/list'.
 */
static void client_list_request(void) {
    
    struct request_list list_packet;
    memset(&list_packet, 0, sizeof(list_packet));
    list_packet.req_type = REQ_LIST;
    sendto(socket_fd, &list_packet, sizeof(list_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Prints out a list of existing channels currently available to the
 * client. The list is extracted from the specified packet received
 * from the server requested from the special command '/list'.
 */
static void server_list_reply(const char *packet) {
    
    int i;
    struct text_list *list_packet = (struct text_list *) packet;
    fprintf(stdout, "Existing channels:\n");
    for (i = 0; i < list_packet->txt_nchannels; i++)
	fprintf(stdout, "  %s\n", list_packet->txt_channels[i].ch_channel);
}

/**
 * Sends a packet to the server requesting a list of users who are currently
 * subscribed to the specified channel. Invoked when the user enters the
 * special command '/who <name>'.
 */
static void client_who_request(const char *request) {
    
    /* Parse the request, return with error if failed */
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }
    /* Create & send the who packet to the server */
    struct request_who who_packet;
    memset(&who_packet, 0, sizeof(who_packet));
    who_packet.req_type = REQ_WHO;
    strncpy(who_packet.req_channel, ++channel, (CHANNEL_MAX - 1));
    sendto(socket_fd, &who_packet, sizeof(who_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Prints out a list of users who are currently subscribed to the specified
 * channel. The list is extracted from the packet received from the server
 * requested from the special command '/who <name>'.
 */
static void server_who_reply(const char *packet) {
    
    int i;
    struct text_who *who_packet = (struct text_who *) packet;
    fprintf(stdout, "Users on channel %s:\n", who_packet->txt_channel);
    for (i = 0; i < who_packet->txt_nusernames; i++)
	fprintf(stdout, "  %s\n", who_packet->txt_users[i].us_username);
}

/**
 * Switched the client's currently active channel to the specified channel.
 * Invoked when the user enters the special command '/switch <name>'. If the
 * client is not subscribed to the specified channel, nothing should happen;
 * just print an error message to the user.
 */
static void client_switch_request(const char *request) {
    
    /* Parse the request, return with error if failed */
    char *channel = strchr(request, ' ');
    if (channel == NULL) {
	fprintf(stdout, "*Unknown command\n");
	return;
    }

    int i;
    ++channel;	/* Skip leading whitespace character */
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], channel) == 0) {
	    /* Channel found in subscription list, switch it to active */
	    memset(active_channel, 0, sizeof(active_channel));
	    strncpy(active_channel, channel, (CHANNEL_MAX - 1));
	    return;
	}
    }	/* Channel not found in list at this point, print status to user */
    fprintf(stdout, "Error: You are not subscribed to the channel %s\n", channel);
}

/**
 * Prints out full list of all the channels the user is currently subscribed
 * to; invoked when the user enters the special command '/subscribed'.
 */
static void client_subscribed_request(void) {
    
    int i;
    fprintf(stdout, "Subscribed channels:\n");
    for (i = 0; i < MAX_CHANNELS; i++) {
	if (strcmp(subscribed[i], "") == 0)
	    continue;	    /* Skip over empty strings */
	if (strcmp(subscribed[i], active_channel) == 0)
	    fprintf(stdout, "* %s\n", subscribed[i]);
	else
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
    fprintf(stdout, "  /clear: Clears the terminal screen.\n");
    fprintf(stdout, "  /help: Lists all available commands.\n");
    fprintf(stdout, "  /exit: Logout and exit the client software.\n");
}

/**
 * Sends a packet to the server requesting the client to log out. Invoked
 * when the user enters the special command '/exit'.
 */
static void client_logout_request(void) {
    
    struct request_logout logout_packet;
    memset(&logout_packet, 0, sizeof(logout_packet));
    logout_packet.req_type = REQ_LOGOUT;
    sendto(socket_fd, &logout_packet, sizeof(logout_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Sends a packet to the server requesting the server to keep the client
 * logged in. Invoked only if the client is inactive for a period of time,
 * that is, they have not sent anything to the server.
 */
static void client_keep_alive_request(void) {
   
    struct request_keep_alive keep_alive_packet;
    memset(&keep_alive_packet, 0, sizeof(keep_alive_packet));
    keep_alive_packet.req_type = REQ_KEEP_ALIVE;
    sendto(socket_fd, &keep_alive_packet, sizeof(keep_alive_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
}

/**
 * Prints out an error message to the client from the specified packet
 * received from the server.
 */
static void server_error_reply(const char *packet) {
    
    struct text_error *error_packet = (struct text_error *) packet;
    fprintf(stdout, "Error: %s\n", error_packet->txt_error);
}

/**
 * Cleans up after the client software; closes the socket stream the client
 * was using and switches terminal back to cooked mode.
 */
static void cleanup(void) {

    if (socket_fd != -1)
	close(socket_fd);
    cooked_mode();
}

/**
 * Function that handles an interrupt signal from the user. Simply exits
 * the program, which will invoke the cleanup method registered with the
 * atexit() function.
 */
static void client_exit(UNUSED int signo) {

    putchar('\n');
    exit(0);
}

/**
 * Prints the specified message to standard error stream as a program error
 * message, then terminates the client application.
 */
static void print_error(const char *msg) {
    
    fprintf(stderr, "[Client]: %s\n", msg);
    exit(0);
}

/**
 * Prints the prompt message, prompting the user for input.
 */
static void prompt(void) {

    fprintf(stdout, "> ");
    fflush(stdout);
}

/**
 * Runs the client system.
 */
int main(int argc, char *argv[]) {

    struct sockaddr from_addr;
    struct hostent *host_end;
    struct request_login login_packet;
    struct request_join join_packet;
    struct timeval timeout;
    socklen_t addr_len = sizeof(server);
    fd_set receiver;
    int port_num, i, j, res;
    char ch;
    char buffer[256], in_buff[BUFF_SIZE];

    /* Assert that the correct number of arguments were given */
    /* Print program usage otherwise */
    if (argc != 4) {
	fprintf(stdout, "Usage: %s server_socket server_port username\n", argv[0]);
	return 0;
    }

    /* Switch terminal to raw mode, terminate if unable */
    if (raw_mode() < 0)
	print_error("Failed to switch terminal to raw mode.");

    /* Register function to cleanup when user stops the client */
    /* Also register the cleanup() function to be invoked upon program termination */
    if (signal(SIGINT, client_exit) == SIG_ERR)
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
    memcpy((char *)&server.sin_addr, (char *)host_end->h_addr_list[0], host_end->h_length);
    server.sin_port = htons(port_num);

    /* Create the client's UDP socket */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	print_error("Failed to create a socket for client.");

    /* Initialize username string, do not copy more bytes than maximum allowed */
    /* Max length specified in duckchat.h */
    strncpy(username, argv[3], (USERNAME_MAX - 1));

    /* Subscribe and join the default channel upon login */
    /* For this assignment, the default channel is named 'Common' */
    strncpy(active_channel, DEFAULT_CHANNEL, (CHANNEL_MAX - 1));
    strncpy(subscribed[0], DEFAULT_CHANNEL, (CHANNEL_MAX - 1));
    /* Opens up all other spots for channels to join */
    for (i = 1; i < MAX_CHANNELS; i++)
	strcpy(subscribed[i], "");

    /* Authenticate the user, ensure the username is not currently taken */
    if (!authenticate_client())
	print_error("The specified username is already in use.");
    /* Send a packet to the server to log user in */
    memset(&login_packet, 0, sizeof(login_packet));
    login_packet.req_type = REQ_LOGIN;
    strncpy(login_packet.req_username, username, USERNAME_MAX);
    sendto(socket_fd, &login_packet, sizeof(login_packet), 0,
		(struct sockaddr *)&server, sizeof(server));
    /* Send a packet to the server to join the default channel */
    memset(&join_packet, 0, sizeof(join_packet));
    join_packet.req_type = REQ_JOIN;
    strncpy(join_packet.req_channel, DEFAULT_CHANNEL, (CHANNEL_MAX - 1));
    sendto(socket_fd, &join_packet, sizeof(join_packet), 0,
		(struct sockaddr *)&server, sizeof(server));

    /* Displays the title and prompt */
    i = 0;
    fprintf(stdout, "---------------  Duck Chat  ---------------\n");
    fprintf(stdout, "Connected to %s:%d\n", inet_ntoa(server.sin_addr), ntohs(server.sin_port));
    fprintf(stdout, "Logged in as %s\n", username);
    fprintf(stdout, "Type '/help' for help, '/exit' to exit.\n");
    prompt();
    /* Set the timeout timer for select() */
    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = KEEP_ALIVE_RATE;

    /**
     * Main application loop. Sends/receives packets to/from the server.
     */
    while (1) {

	/* Watch either the stdin or the socket stream for input */
	FD_ZERO(&receiver);
	FD_SET(socket_fd, &receiver);
	FD_SET(STDIN_FILENO, &receiver);
	res = select((socket_fd + 1), &receiver, NULL, NULL, &timeout);

	/* Select() timed out, user has not sent packet */
	/* Send a keep-alive packet to server, reset the timer */
	if (res == 0) {
	    client_keep_alive_request();
	    timeout.tv_sec = KEEP_ALIVE_RATE;
	}

	/* Either data arrived in stdin or socket stream */
	else if (res > 0) {
	    
	    /**
	     * Input was received from the socket stream, a message arrived to the client.
	     *
	     * The message is received with recvfrom(), and the type of message is parsed by
	     * the 32-bit identifier. The rest of the packet is then dealt with accordingly.
	     */
	    if (FD_ISSET(socket_fd, &receiver)) {

		/* Receive incoming packet, parse the identifier */
		memset(in_buff, 0, sizeof(in_buff));
		if (recvfrom(socket_fd, in_buff, sizeof(in_buff), 0,
				&from_addr, &addr_len) < 0) continue;
		struct text *packet_type = (struct text *) in_buff;

		/* Erases all typed text in the prompt to make space for message */
		for (j = 0; j < (i + 2); j++) {
		    putchar('\b'); putchar(' '); putchar('\b');
		}

		switch (packet_type->txt_type) {
		    case TXT_SAY:
			/* Message received from another client */
			server_say_reply(in_buff);
			break;
		    case TXT_LIST:
			/* List server's available channels */
			server_list_reply(in_buff);
			break;
		    case TXT_WHO:
			/* List users on a server's channel */
			server_who_reply(in_buff);
			break;
		    case TXT_ERROR:
			/* Error message received from the server */
			server_error_reply(in_buff);
			break;
		    default:
			/* Do nothing, likely a bogus packet */
			break;
		}

		/* Redisplays the prompt and all text the user typed in before */
		prompt();
		for (j = 0; j < i; j++)
		    putchar(buffer[j]);
		fflush(stdout);
	    }

	    /**
	     * Input was received from the stdin stream, user entered a character.
	     */
	    if (FD_ISSET(STDIN_FILENO, &receiver)) {
		
		if ((ch = getchar()) != '\n') {
		    if (ch == 127) {
			/* User pressed backspace, erase character from prompt */
			if (i == 0)
			    continue;
			i--;
			putchar('\b'); putchar(' '); putchar('\b');
		    } else if (i != (SAY_MAX - 1)) {
			/* Display character on prompt, add to buffer */
			buffer[i++] = ch;
			putchar(ch);
		    } 
		    fflush(stdout);
		    continue;
		}
		
		/* End user input with null byte for string comparisons */
		buffer[i] = '\0';
		i = 0;
		putchar('\n');

		/* If the first character of input is '/', interpret as special command */
		if (buffer[0] == '/') {
		    if (strncmp(buffer, "/join ", 6) == 0) {
			/* User joins/subscribes to a channel */
			client_join_request(buffer);
		    } else if (strncmp(buffer, "/leave ", 7) == 0) {
			/* User unsubscribes from a channel */
			client_leave_request(buffer);
		    } else if (strcmp(buffer, "/list") == 0) {
			/* User requests list of all channels on server */
			client_list_request();
		    } else if (strncmp(buffer, "/who ", 5) == 0) {
			/* User requests list of users on a channel */
			client_who_request(buffer);
		    } else if (strncmp(buffer, "/switch ", 8) == 0) {
			/* User switches active channel to another channel */
			client_switch_request(buffer);
		    } else if (strcmp(buffer, "/subscribed") == 0) {
			/* User lists their subscribed channels */
			client_subscribed_request();
		    } else if (strcmp(buffer, "/clear") == 0) {
			/* User clears the prompt */
			system("clear");
		    } else if (strcmp(buffer, "/help") == 0) {
			/* User prints help message */
			client_help_request();
		    } else if (strcmp(buffer, "/exit") == 0) {
			/* User exits the client */
			client_logout_request();
			break;
		    } else {
			/* Unknown special command */
			fprintf(stdout, "*Unknown command\n");
		    }
		} else {
		    /* No special command given, send say message to server */
		    client_say_request(buffer);
		}
		prompt();
	    }
	}
    }

    return 0;
}
