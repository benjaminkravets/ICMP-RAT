# ICMP-RAT
Linux kernel module client that gets payload commands with netfilter hooks from a Scapy client.

This repo has a server side (the kernel module that is built and inserted into a Linux box) and the client side (the Scapy based Python3 script used to send commands). 

To set up:
Linux (server) side:
```
user@yourbox:~/dir$ git clone https://github.com/benjaminkravets/ICMP-RAT.git
user@yourbox:~/dir$ cd /ICMP-RAT/servermodule
user@yourbox:~/dir/ICMP-RAT/servermodule$ make 
```

