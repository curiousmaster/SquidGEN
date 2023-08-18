#======================================================================
# This directory contains csv files (extension .conf) that defines the
# ruleset
# The first line must be a three column header with "src,dst,port"
#
# src:  ip, ip-range, cidr, resolvable hostname, or a list of the previous
# dst:  ip, ip-range, cidr, resolvable hostname, or a list of the previous
# port: port, port-range, or a list of the previous
#----------------------------------------------------------------------
# Example:
#--------------------------------------------------
#src,dstdomain,port
#192.168.1.120-192.168.1.130,.acme.com,80 443
#192.168.200.0/24,.kali.org,80 443
#laptop.internal,debian.org,80 443
#----------------------------------------------------------------------
