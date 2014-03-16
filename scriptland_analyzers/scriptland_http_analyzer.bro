@load ./raw

module Analyzer;

export {
	global session_taster: function(c: connection, is_orig: bool);
	
	# these regexes are lame, don't trust them
	global orig_check: pattern = /.*HTTP/;
	global resp_check: pattern = /.*HTTP/;
}

function session_taster(c: connection, is_orig: bool)
{
	if (is_orig)
	{
		if (Analyzer::orig_check in c$raw$orig_tcp_data)
		{
			print "ORIG HTTP";
		} 
	} else
	{
		if (Analyzer::resp_check in c$raw$resp_tcp_data)
		{
			print "RESP HTTP";
		} 
	}
}


event connection_state_remove(c: connection)
{
        if (c$conn$proto == tcp)
        {
                if (|c$raw$orig_tcp_data| > 0)
                {
			Analyzer::session_taster(c, T);
                }
                if (|c$raw$resp_tcp_data| > 0)
                {
			Analyzer::session_taster(c, F);
                }
        }
}

