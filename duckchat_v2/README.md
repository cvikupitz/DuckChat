# DuckChat v2

## O.S.
This application was built to run on Linux platforms. It does not run on Windows.
I have not tested it on any other operating system.

## Make Instructions
To compile the whole application, type 'make all'.
You may also type 'make client' and 'make server' to compile the client and server separately.
You can also type 'make help' for more options.

## Usage Instructions
To use the application, first run the server(s), then run as many clients as you want.

Usage to run the server is as follows:

`$ ./server domain_name port_number [domain_name port_number]`

where the first two arguments are the host address to bind to, and the port number. The following argument
pair(s) are optional, and are the host address and port numbers that the neighboring server(s) connect to.
You may pass in as many pairs as you need.

For example, to create a server topology like the one shown below:

    4000 ----- 4001 ----- 4002

You must run the following commands:

`
$ ./server localhost 4000 localhost 4001
$ ./server localhost 4001 localhost 4000 localhost 4002
$ ./server localhost 4002 localhost 4001
`

Usage to run the client is as follows:

`$ ./client server_socket server_port username`

where the arguments are the hostname the server is running on, the port number the server is listening
on, and the client's username.

## Using the Server
The server(s) will run on their own and requires no user input.
To end a server session, press CTRL+C or send a SIGINT to the running process.

## Using the Client
To send a message, simply type the message and press enter. The message you send will be sent to all other
clients listening on the current channel. The client supports a number of special commands that are listed
as such below:

* /join [channel]: Join the named channel, creating it if it doesn't exist.
* /leave [channel]: Unsubscribe from the named channel.
* /list: Lists the names of all the available channels.
* /who [channel]: Lists all users who are on the named channel.
* /switch [channel]: Switch to the named channel you are subscribed to.
* /subscribed: Lists the names of all the channels you're subscribed to.
* /clear: Clears the terminal screen.
* /help: Lists all available commands.
* /exit: Logout and exit the client software.

## Resources
A lot of help consulted from Beej's Guide to Network/Socket Programming
http://beej.us/guide/bgnet/output/html/multipage/index.html

The LinkedList and HashMap implementations used by the server are borrowed from professor Joe Sventek's
C ADT library (https://github.com/jsventek/ADTs). Credit belongs to him.

