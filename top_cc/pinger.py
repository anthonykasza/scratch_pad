#!/usr/bin/python
 
from scapy.all import *
import random
import time
 
src_ip_addr = "10.0.0.1"
destp = 80
srcp = 25252
 
while (1):
        o1 = str( random.randint(1,255) )
        o2 = str( random.randint(1,255) )
        o3 = str( random.randint(1,255) )
        o4 = str( random.randint(1,255) )
 
        dst_ip_addr = o1 + "." + o2 + "." + o3 + "." + o4
 
        print "sending FA to", dst_ip_addr, ":", destp, "from", src_ip_addr, ":", srcp
        pkt = IP(dst=dst_ip_addr, src=src_ip_addr)/TCP(dport=destp, sport=srcp, flags="FA")
        send(pkt)
        time.sleep(1)
