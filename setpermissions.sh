#! /usr/bin/bash

groupadd squidadm

chgrp -r squidadm bin
usermod -a -G squidadm sysadmin

cat > /etc/sudoers.d/squidadm <<_EOF_
%squidadm ALL=(ALL:ALL) NOPASSWD:/etc/squid/bin/*
_EOF_
chmod 755 bin/*
chgrp -r squidadm rules.d
chmod 770 rules.d
