#!/bin/bash
PORT=8080
while netstat -anT | grep -q ":$PORT "; do
  PORT=$((PORT+1))
done
echo $PORT
