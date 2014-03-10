## CAUTION: 	This script is meant for analyzing trace files and can be harmful if ran on live networks.
## 		Working with the tcp_contents event can be expensive.
#

redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;

module TcpPayloads;

export {
	redef record connection += {
		orig_tcp_data: string &default="";
		resp_tcp_data: string &default="";
	};
	
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
{
	# contents values are the same data that is passed on to protocol analyzers internally in Bro's core
	# scriptland protocol analyzers can hook in here

	if (is_orig)
	{
#		c$orig_tcp_data = fmt("%s%s", c$orig_tcp_data, string_to_ascii_hex(contents));
		c$orig_tcp_data = fmt("%s%s", c$orig_tcp_data, contents);
	} else
	{
#		c$resp_tcp_data = fmt("%s%s", c$resp_tcp_data, string_to_ascii_hex(contents));
		c$resp_tcp_data = fmt("%s%s", c$resp_tcp_data, contents);
	}
}
