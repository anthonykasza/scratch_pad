@load frameworks/intel/seen
@load base/frameworks/intel
@load frameworks/intel/seen/where-locations

# public_suffix.bro should probably be read in with the input framework instead of loaded like it is
@load public_suffix

function tldr(s: string): string
{
        if ( (/\./ !in s) || (s in suffixes) )
                return s;

        return tldr( split1(s, /\./)[2] );
}

redef Intel::read_files += {
        fmt("%s/intel-1.dat", @DIR)
};

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
	Intel::seen([$indicator=tldr(query), 
		$indicator_type=Intel::DOMAIN,
		$conn=c,
		$where=DNS::IN_REQUEST]);
}

