#! /usr/bin/sh

/etc/squid/bin/squid-genrules.py
/usr/sbin/squid --foreground -
