#! /usr/bin/sh

/etc/squid/bin/squid-genrules.py
sleep 1
systemctl reload squid
