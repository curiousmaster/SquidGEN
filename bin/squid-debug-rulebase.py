#!  /usr/bin/python3
#======================================================================
# NAME
#   debug-rulebase.py   - Run debug on Squid Rulebase
#
# DESCRIPTION
#   This script will search Squid cache.log for rulebase findings. To
#   enable logging in Squid set debug_options to "28,3"
#
#   :
#   debug_options = 28,3
#   :
#
# OPTIONS
#   -h, --help         show this help message and exit
#   -s IP, --src IP    set search for IP address
#   -l LOG, --log LOG  Search LOG file
#
# AUTHOR
#   Stefan Benediktsson / Defensify AB
#
# HISTORY
#   v1.0    - Feb 10, 2023 - Initial Version
#
# CAVEATS
#   This is an unsupported script, and highly dependant on the log format.
#
#======================================================================

import re
import argparse
import sys

CACHELOG="/var/log/squid/cache.log"
IP="127.0.0.1"

#--------------------------------------------------
# getArguments()
#   Read command line arguments
#--------------------------------------------------
def getArguments():
    global CACHELOG
    global IP
    parser = argparse.ArgumentParser(
        prog = 'debug-squid.py', description='Debug Squid ruleset', epilog=''
    )
    #------------------------------
    # Set IP
    #------------------------------
    parser.add_argument(
        '-s', '--src',
        metavar='IP',
        help='set search for IP address',
        dest='IP',
        default=IP,
        required=True)
    #------------------------------
    # Set CACHELOG
    #------------------------------
    parser.add_argument(
        '-l', '--log',
        metavar='LOG',
        help='Search LOG file',
        dest='CACHELOG',
        default=CACHELOG,
        required=False)
    args = parser.parse_args()
    IP = args.IP
    CACHELOG = args.CACHELOG


#======================================================================
# match_ip_address()
#   find given IP address in string
#======================================================================
def match_ip_address(string, target_ip):
    if "lookup" in string:
        pattern = r'\b' + target_ip + r'\b'
        match = re.search(pattern, string)
        if match:
            return True
        return False
    else:
        return False


#======================================================================
# get_time_from_log_line()
#   Get the time entry from the string
#======================================================================
def get_time_from_log_line(string):
    if "kid1" in string:
        index = string.index("kid1")
        date = string[:index]
        return date
    else:
        return False


#======================================================================
# read_log_file
#   Parse the logfile and output events matching a given IP address
#======================================================================
def read_log_file(file_name, ip_address):
    LOG = []
    with open(file_name, "r") as file:
        # Read all lines in the file
        lines = file.readlines()
        # Iterate through all lines
        for line in lines:
            match = match_ip_address(line,ip_address)
            # If the line matches the pattern, extract the time and search for all matching lines
            if match:
                time = get_time_from_log_line(line)
                # Iterate through all lines again to find matching lines
                for line in lines:
                    if time in line:
                        line = line.replace(" kid1| 28,3|",":")
                        date, line = line.split(": ",1)
                        LOG.append([date,line])
        return LOG


#======================================================================
# create_dict()
#======================================================================
def create_dict(list_of_lists):
    result = {}
    for sub_list in list_of_lists:
        if sub_list[0] in result:
            result[sub_list[0]].append(sub_list[1])
        else:
            result[sub_list[0]] = [sub_list[1]]
    return result


#======================================================================
# evalEvent()
#======================================================================
def evalEvent(line):
    line = line.strip()
    ret = False
    t = ""
    if "access_log" in line:
        #------------------------------
        # Discard
        #------------------------------
        ret = False
    elif "lookup:" in line:
        #------------------------------
        # Client IP address
        #------------------------------
        t = "0:source"
        s = line[line.index(IP):]
        s = s[:s.index(" ")]
        ret = s
    elif "aclIpMatchIp:" in line:
        #------------------------------
        # Discard
        #------------------------------
        ret = False
    elif "aclMatchDomainList:" in line:
        #------------------------------
        # Domain
        #------------------------------
        if "checking" in line:
            t = "1:destination"
            si = line.find('\'') + 1
            ei = line.rfind('\'')
            s = line[si:ei]
            ret = s
        else:
            ret = False
    elif "matches:" in line:
        #------------------------------
        # Rule / ACL
        #------------------------------
        if "http_access" in line:
            t = "3:rule"
        else:
            t = "2:acl"
        s = line.split(": ",)
        s = s[len(s)-1]
        rule, result =  s.split(" = ")
        ret = rule.ljust(25) + ": " + result
    elif "checkCallback:" in line:
        #------------------------------
        #------------------------------
        t = "9:action"
        s = line[line.index("=")+1:]
        ret = s
    return t, ret


#======================================================================
# main()
#   Main function
#======================================================================
def main():
    global CACHELOG
    global IP
    getArguments()
    LOG = read_log_file(CACHELOG, IP)
    LOG = create_dict(LOG)
    for EVENT in LOG:
        event = LOG[EVENT]
        squid_event=[]
        print('--------------------------------------------------')
        print(f'DATE: {EVENT}')
        for line in event:
            line = line.strip()
            t, line = evalEvent(line)
            if line:
                t=t.ljust(15)
                squid_event.append(f'{t}: {line}')
        squid_event.sort()
        for event in squid_event:
            event = event.strip().split(":",1)
            print(f'{event[1]}')


#======================================================================
# Run main function
#======================================================================
if __name__ == "__main__":
    main()
