#! /usr/bin/bash

#======================================================================
# Create group and add sysadmin
#======================================================================
groupadd squidadm
usermod -a -G squidadm sysadmin

#======================================================================
# Setup sudo for sysadmin
#======================================================================
cat > /etc/sudoers.d/squidadm <<_EOF_
%squidadm ALL=(ALL:ALL) NOPASSWD:/etc/squid/bin/*
_EOF_
chmod 400 /etc/sudoers.d/squidadm

#======================================================================
# Change permissions of environment
#======================================================================
chmod 750 bin/*
chgrp squidadm bin
chgrp squidadm bin/*

chmod 770 rules.d
chmod 660 rules.d
chgrp squidadm rules.d
chgrp squidadm rules.d/*

cp -rp autogenerated.d bin conf.d rules.d squid.conf /etc/squid

#======================================================================
# Change service for Squid
#======================================================================
mv /usr/lib/systemd/system/squid.service /usr/lib/systemd/system/squid.service-dist
cp usr/lib/systemd/system/squid.service /usr/lib/systemd/system/squid.service 

systemctl daemon-reload
