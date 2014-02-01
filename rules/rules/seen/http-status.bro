@load base/frameworks/intel
@load ./where-locations

event http_reply(c: connection, version: string, code: count, reason: string)
{
	Intel::seen([$indicator=fmt("%d", code),
		$indicator_type=Intel::RETURN_CODE,
		$conn=c,
		$where=HTTP::IN_STATUS_CODE]);
}
