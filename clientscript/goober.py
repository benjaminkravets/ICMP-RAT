#!/usr/bin/env
import sys
import getopt
from scapy.all import *
from ipaddress import IPv4Address
import sys
import getopt
remote_ip = None
command = None
time_out = None
  
def full_name():
    first_name = None
    last_name = None
  
    argv = sys.argv[1:]
    global remote_ip
    global command
    global time_out
  
    try:
        opts, args = getopt.getopt(argv, "i:c:t:", 
                                   ["remote_ip =",
                                    "command =",
                                    "timeout ="])
        for opt, arg in opts:
        
            if opt in ['-i', '--remote_ip']:
                try:
                    remote_ip = IPv4Address(arg)
                except:
                    print("Invalid IP")
                    sys.exit()
            if opt in ['-c', '--command']:
                command = arg
            elif opt in ['-t', '--timeout']:
                time_out = int(arg)
        
  
        
    except Exception as e:
        print("Remote IP (-i) and command (-c) are required")
        print(e)


def send_command():
        
        pack = srp1(Ether()/IP(dst=str(remote_ip))/(ICMP()/command),timeout=time_out)
        print(time_out)
        try:
        #pack.show()
                sys.exit()
        except Exception as e:
                print(e)
                print("no reply")
                sys.exit()

full_name()
send_command()

