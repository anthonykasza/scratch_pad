Bro's input framework reads files asynchronously. See [here](http://www.bro.org/sphinx/input.html)

If using the input framework within a Bro script and running Bro against a small PCAP, often Bro will terminate before the input framework finishes reading in whatever file. 
suspend_input_continue is an example script that solves this problem.

Usage
====
Suspend packet processing until the input framework completes, then continue packet processing. 

	chmod +x blacklist_builder.sh
	./blacklist_builder.sh > blacklist.file
	bro -r small.pcap suspend_input_continue.bro
