module DNS;

export {
	type Cache_Object: record {
		dns_domain:		string;
		dns_uid:	string;
	};

	redef record connection += { 
		dns_uid: string &optional; 
		dns_domain: string &optional;
	};
	redef record Conn::Info += { 
		dns_uid: string &optional &log; 
		dns_domain: string &optional &log;
	};

	type Asker_Index: table[addr] of Cache_Object;
	global dns_cache: table[addr] of Asker_Index &create_expire = 30 secs;
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
	if (msg$num_answers < 1)
	{
		return;
	}
	
	local tmp_asker_index: DNS::Asker_Index;
	tmp_asker_index[c$id$orig_h] = [$dns_domain=ans$query, $dns_uid=c$uid];
	DNS::dns_cache[a] = tmp_asker_index;
}

event new_connection(c: connection)
{
	if (c$id$resp_h !in DNS::dns_cache)
	{
		return;
	}

	if (c$id$orig_h !in DNS::dns_cache[c$id$resp_h]) 
	{
		return;
	} else 
	{
		c$dns_uid = DNS::dns_cache[c$id$resp_h][c$id$orig_h]$dns_uid;
		c$dns_domain = DNS::dns_cache[c$id$resp_h][c$id$orig_h]$dns_domain;
	}
}	

event connection_state_remove(c: connection)
{
	if (! (c?$dns_uid || c?$dns_domain) )
	{
		return;
	}
	c$conn$dns_uid = c$dns_uid;
	c$conn$dns_domain = c$dns_domain;
}
