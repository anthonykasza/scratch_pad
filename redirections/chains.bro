
# once my pull request for changes in base/utils/urls.bro is merged, this can be removed
@load ./urls

module Redirects;

export {
	type http_pivot: record {
		uri:	string;
		domain:	string;
		uid: 		string;
	};

	type dns_pivot: record {
		domain:	string;
		uid:	string;
	};

	redef record connection += { 
		dns_precede:	dns_pivot &optional;
		http_precede:	http_pivot &optional;
	};

	redef record Conn::Info += { 
		dns_domain:	string &log &optional;
		dns_uid:	string &log &optional;

		http_uri:	string &optional &log;
		http_domain:	string &optional &log;
		http_uid:	string &optional &log;
	};

	type dns_query_index: table[addr] of dns_pivot;
	global dns_cache: table[addr] of dns_query_index &create_expire=5secs;
	global http_location_cache: table[addr] of http_pivot &create_expire=5secs;

	# threshold for redirect chain length
	# 2 UIDs are needed to visit 1 webiste via dns+http, so you might consider dividing chain lengths by 2
	# 4 allows for a single redirect
	global max_chain_len: count = 2;

	# function to add uid links to chain table
	global add_uid_link: function(preceding_uid: string, subsequent_uid: string);

	# expire function for chains
	global check_chain_len: function(chains: table[string] of vector of string, chain: vector of string): interval;

	# table of chains indexed by last link in chain
	global chains: table[string] of vector of string &create_expire=15secs &expire_func=check_chain_len;
}

function check_chain_len(chains: table[string] of vector of string, chain: vector of string): interval
	{
	if (|chain| > max_chain_len)
		{
		# PANIC! (or raise a notice) 
		print chain;
		}
	# do not wait any longer to expire the chain
	return 0secs;
	}

function add_uid_link(preceding_uid: string, subsequent_uid: string)
	{
	if (preceding_uid in chains)
		{
			local idx: count = |chains[preceding_uid]|;
			chains[preceding_uid][idx] = subsequent_uid;
			chains[subsequent_uid] = chains[preceding_uid];
			delete chains[preceding_uid];

########## This should be removed ################################
			if (|chains[subsequent_uid]| > max_chain_len)
				{
				# PANIC! (or raise a notice) 
				print chains[subsequent_uid];
				}
##################################################################

		}
	else
		{
			chains[subsequent_uid] = vector(preceding_uid, subsequent_uid);
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( (qtype != 1) || (qclass != 1) || (c$id$orig_h !in http_location_cache) ) # not class IN or not type A
		{
		return;
		}
	c$http_precede=http_location_cache[c$id$orig_h];
	add_uid_link(c$http_precede$uid, c$uid);
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	if (msg$num_answers < 1)
		{
		return;
		}
	
	local tmp_dns_query_index: dns_query_index;
	tmp_dns_query_index[c$id$orig_h] = [$domain=ans$query, $uid=c$uid];
	dns_cache[a] = tmp_dns_query_index;
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( (is_orig) || (name != "LOCATION") )
		{
		return;
		}
	http_location_cache[c$id$orig_h] = [$uri=value, $domain=decompose_uri(value)$netlocation, $uid=c$uid];
	}

event new_connection(c: connection)
	{
	if (c$id$resp_h !in dns_cache)
		{
		return;
		}

	if (c$id$orig_h !in dns_cache[c$id$resp_h]) 
		{
		return;
		} 
	else 
		{
		c$dns_precede = [$uid=dns_cache[c$id$resp_h][c$id$orig_h]$uid,
			$domain = dns_cache[c$id$resp_h][c$id$orig_h]$domain];
		add_uid_link(c$dns_precede$uid, c$uid);
		}
	}	

event connection_state_remove(c: connection)
	{
	if (c?$dns_precede)
		{
		c$conn$dns_domain = c$dns_precede$domain;
		c$conn$dns_uid 	  = c$dns_precede$uid;
		}

	if (c?$http_precede)
		{
		c$conn$http_uri = c$http_precede$uri;
		c$conn$http_domain = c$http_precede$domain;
		c$conn$http_uid = c$http_precede$uid;
		}
	}
