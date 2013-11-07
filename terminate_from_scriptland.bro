redef exit_only_after_terminate = T;

function custom_bro_done()
{
	print "custom_bro_done";
	terminate();
}

bro_init()
{
	print "bro_init";
	custom_bro_done();
}

event bro_done()
{
	print "bro_done";
}
