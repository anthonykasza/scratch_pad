# this script will count HTTP connections over 5 second intervals. HTTP connections are inspected for:
# 	the domain from the DNS query preceding the HTTP connection
#	the host header field
#	the user-agent field
#


@load base/frameworks/sumstats
@load ./dns_conn_cache

module HttpDomains;

export {

	# alter the interval time to make this script useful
	const hd_interval: interval = 5 secs;

}

event bro_init() &priority=5
{
	local r1: SumStats::Reducer = [$stream="hd", $apply=set(SumStats::UNIQUE)];

	SumStats::create( [$name="hd",
				$epoch=hd_interval,
				$reducers=set(r1),
				$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
				{
					for (each in result)
					{
						local d: string = split(key$str, /:::/)[1];
						local h: string = split(key$str, /:::/)[2];
						print fmt("domain %s was visited: %d times (with host field %s)", d, result[each]$num, h);
						for (ua_each in result[each]$unique_vals)
						{
							print fmt("        with user_agent: %s", ua_each$str);
						}
					}
				},
				$epoch_finished(ts: time) =
				{
					print fmt("=============NEXT %s TIME SLICE===============", hd_interval);
				}
	] );
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
	# if this is a server response, we don't care about it
	if (! is_orig)
	{
		return;
	}

	# if this http stuff was generated without an associated domain or user-agent, we don't care about it
	if ( (c?$dns_domain) && (c?$http) && (c$http?$user_agent) )
	{
		SumStats::observe("hd", [$str=fmt("%s:::%s", c$dns_domain, c$http$host)], [$str=c$http$user_agent]);
	}
}

