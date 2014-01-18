@load base/frameworks/intel
@load base/protocols/http/utils
@load ./where-locations

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig && c?$http && c$http?$uri )
		Intel::seen([$indicator=c$http$uri,
		             $indicator_type=Intel::URL_PATH,
		             $conn=c,
		             $where=HTTP::IN_URL_PATH]);
	}
