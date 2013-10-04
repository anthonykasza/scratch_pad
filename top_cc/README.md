Top Country Code
================
This code is meant to provide examples on how to use the top k data type. It also shows how an event can schedule itself to create a control flow similar to a while loop combined with a sleep command.

Description
-----------
*pinger.py* sends FIN+ACK packets to random IP addresses from an RFC1918 address.
*topc_cc.bro* draws a rudimentary graph for the top K countries sent packets.

Requirements
------------
-The Scapy Python module
-GeoIP enabled Bro 

Usage
-----

	sudo python pinger.py
	sudo bro -i ethX top_cc.bro

If Bro complains about checksums in the above command, run it with the -C option.
