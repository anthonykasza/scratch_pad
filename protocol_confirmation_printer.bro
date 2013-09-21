##! These events are deprecated

# this script will print stuff when bro identifies the protocol used in a connection

#@load policy/frameworks/dpd/detect-protocols
#@load base/frameworks/dpd

redef ignore_checksums = T;

event protocol_violation(c: connection, atype: count, aid: count, reason: string)
{
#	print atype;
#	print dpd_config[atype];
#	print ( analyzer_name(aid) );
#	print reason;
}

event protocol_confirmation(c: connection, atype: count, aid: count)
{
	#print c;
	#print atype;
	#print ( analyzer_name(aid) );
}
