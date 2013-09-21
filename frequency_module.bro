##! This code is obsoleted by the SumStats framework
##!
##! This module will count the frequencies of connections from an origin to a responder
##! As the source port of a client usually changes each connection it is not included in the Freq::Info enum
##!
##! This script does not count responses. Ever. For anything. If a connection originator (as seen by Bro) is not
##! 	a true connection originator, this script lies to you.
##! This script, as with all of Bro, sees UDP and ICMP is terms of connections, remember that when considering 
##!	stats about an originator when port types are /udp or /icmp
##!

module Freq;
export {
#	redef enum Log::ID += { LOG };
	type Info: record {
		orig_h: addr	&log;
		resp_h: addr	&log;
		resp_p: port	&log;
	};
	type Stats: record {
		conns:		count &log;	
		orig_bytes_ip: 	count &log;
		orig_pkts: 	count &log;
	};
#	global log_freq: event(rec: Info);
}

# This global table contains indices of Freq::Info (sip, dip, dport) which yield a frequency count
global conn_freq: table[Freq::Info] of Freq::Stats &redef;
# This makes counting packets by endpoints something something
#	http://bro-project.org/documentation/scripts/base/init-bare.html#id-use_conn_size_analyzer
redef use_conn_size_analyzer = T;

event connection_state_remove(c: connection)
{
	local temp_info: Freq::Info = [$orig_h = c$id$orig_h, $resp_h = c$id$resp_h, $resp_p = c$id$resp_p];
	local temp_stats: Freq::Stats = [$conns = 1, $orig_bytes_ip = c$orig$num_bytes_ip , $orig_pkts = c$orig$num_pkts ];
	if (temp_info in conn_freq) {
		conn_freq[temp_info]$conns += temp_stats$conns;
		conn_freq[temp_info]$orig_bytes_ip += temp_stats$orig_bytes_ip;
		conn_freq[temp_info]$orig_pkts += temp_stats$orig_pkts;
	}
	else {
		conn_freq[temp_info] = temp_stats;
	}
	
}

#event bro_init() &priority=5
#{
#	Log::create_stream(Freq::LOG, [$column=Info, $ev=log_freq]);
#}

event bro_done()
{
	local conn_freq_size: count = |conn_freq|;
	print fmt("the unique client to server:port connections is %d", conn_freq_size);
	for (each in conn_freq) {
		print fmt( 
			"%s connected to port %s on %s: %d time, sent %d pkts, which totalled %d (IP and above) bytes.", 
			each$orig_h, each$resp_p, each$resp_h, 
			conn_freq[each]$conns, conn_freq[each]$orig_pkts, conn_freq[each]$orig_bytes_ip
		);
	}
}
