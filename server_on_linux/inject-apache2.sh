#!/bin/bash

make
KILL_ID=`ps -ef|grep /usr/sbin/apache2|grep -v grep|awk '{print $2}'` 
for kill_id in $KILL_ID
do
kill -9 $kill_id
echo "kill pid =" $kill_id
done
service apache2 stop
service apache2 start
sleep 2s
ID=`ps -ef|grep /usr/sbin/apache2|grep -v grep|awk '{print $2}'` 
for id in $ID
do
echo "inject pid =" $id
./inject -p $id ./injectme.so
done
