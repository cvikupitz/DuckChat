#!/usr/bin/bash

# Change the SERVER variable below to point your server executable.
SERVER=./server

SERVER_NAME=`echo $SERVER | sed 's#.*/\(.*\)#\1#g'`

# Single server
#$SERVER localhost 4000 &

# Generate a simple two-server topology
#$SERVER localhost 4000 localhost 4001 &
#$SERVER localhost 4001 localhost 4000 &

# Generate a simple 3-server lined topology
#$SERVER localhost 4000 localhost 4001 &
#$SERVER localhost 4001 localhost 4000 localhost 4002 &
#$SERVER localhost 4002 localhost 4001 &

# Generate a triangular topology
$SERVER localhost 4000 localhost 4001 localhost 4002 &
$SERVER localhost 4001 localhost 4000 localhost 4002 &
$SERVER localhost 4002 localhost 4001 localhost 4000 &

# Generate a square-shaped topology
#$SERVER localhost 4000 localhost 4001 localhost 4002 &
#$SERVER localhost 4001 localhost 4000 localhost 4003 &
#$SERVER localhost 4002 localhost 4000 localhost 4003 &
#$SERVER localhost 4003 localhost 4001 localhost 4002 &

# Generate a capital-H shaped topology
#$SERVER localhost 4000 localhost 4001 &
#$SERVER localhost 4001 localhost 4000 localhost 4002 localhost 4003 &
#$SERVER localhost 4002 localhost 4001 & 
#$SERVER localhost 4003 localhost 4001 localhost 4005 &
#$SERVER localhost 4004 localhost 4005 &
#$SERVER localhost 4005 localhost 4004 localhost 4003 localhost 4006 &
#$SERVER localhost 4006 localhost 4005 &

# Generate a 3x3 grid topology
#$SERVER localhost 4000 localhost 4001 localhost 4003 &
#$SERVER localhost 4001 localhost 4000 localhost 4002 localhost 4004 &
#$SERVER localhost 4002 localhost 4001 localhost 4005 &
#$SERVER localhost 4003 localhost 4000 localhost 4004 localhost 4006 &
#$SERVER localhost 4004 localhost 4001 localhost 4003 localhost 4005 localhost 4007 &
#$SERVER localhost 4005 localhost 4002 localhost 4004 localhost 4008 &
#$SERVER localhost 4006 localhost 4003 localhost 4007 &
#$SERVER localhost 4007 localhost 4006 localhost 4004 localhost 4008 &
#$SERVER localhost 4008 localhost 4005 localhost 4007 &


echo "Press ENTER to quit"
read
pkill $SERVER_NAME
