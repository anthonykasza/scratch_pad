Tx Baseline
===========
This code is meant to provide examples on how to use the SumStats framework. The script will determine the total amount of bytes each host sends per day and the average amount of bytes each host sends per week. The script is configured to use minutes instead of days for illustation.

Usage
-----
	sudo bro -i ethX txbaseline.bro

If Bro complains about checksums in the above comand, run it with the -C option. The SumStats framework like to see traffic, so feed it some by pinging a few things while running this script.

ToDo
----
- Determine how to incorporate the STD_DEV plugin to determine if a host has sent an abnormal (more than one standard deviation) amount of traffic compared to similar days of the week in the year. How many bytes does this IP address normally send on a Wednesday? Is this IP sending more or less than usual or an acceptable deviation?
