## CAUTION: 	This script is meant for analyzing trace files and can be harmful if ran on live networks.
## 		Working with the tcp_contents event can be expensive.
#

module Raw;

export {

	type Info: record {
		orig_tcp_data: string &default="";
		resp_tcp_data: string &default="";
	};
}

redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;

redef record connection += {
	raw: Info &optional;
};

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
{
	if (! c?$raw)
	{
		local tmp: Raw::Info;
		c$raw = tmp;
	}	
	# contents values are the same data that is passed on to protocol analyzers internally in Bro's core
	# scriptland protocol analyzers can hook in here
	if (is_orig)
	{
		c$raw$orig_tcp_data = fmt("%s%s", c$raw$orig_tcp_data, contents);
	} else
	{
		c$raw$resp_tcp_data = fmt("%s%s", c$raw$resp_tcp_data, contents);
	}
}
