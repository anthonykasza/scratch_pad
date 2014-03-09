## CAUTION: 	This script is meant for analyzing trace files and can be harmful if ran on live networks.
## 		Working with the tcp_contents event can be expensive.
#

redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;

module TcpPayloads;

export {
	global default_tcp_data: table[count] of string = {[0]=""};

	redef record connection += {
		tcp_data: table[count] of string &default=default_tcp_data;
	};
	
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
{
	c$tcp_data[seq] = string_to_ascii_hex(contents);
}

event connection_state_remove(c: connection)
{
	if (c$conn$proto == tcp)
	{
		print c$tcp_data;
	}
}
