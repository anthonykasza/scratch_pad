type Idx: record {
	ip: addr;
};
type Val: record {
	timestamp:	time;
	reason:		string;
};
global blacklist: table[addr] of Val = table();

event bro_init()
{
	suspend_processing();

	Input::add_table( [$source="blacklist.file", $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist] );
	Input::remove("blacklist");

	when (|blacklist| > 0)
	{
		continue_processing();
	}
}

event new_connection(c: connection)
{
	if (c$id$resp_h in blacklist)
	{
		print "connection to blacklisted IP";
	}
}
