#!/bin/bash

make
KILL_ID=`ps -ef|grep /usr/sbin/ssh|grep -v grep|awk '{print $2}'`
for id in $KILL_ID 
do
kill -9 $id
echo "kill pid =" $id
done
service sshd stop 
service sshd start 
ID=`ps -ef|grep /usr/sbin/ssh|grep -v grep|awk '{print $2}'` 
echo "ssh pid =" $ID
./inject -p $ID ./injectme.so
