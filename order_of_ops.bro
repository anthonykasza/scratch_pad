module UniqueModuleName1234;

export {
	global foo: string = "foo";
#	print "you cannot print from an export block :(";
}

event bro_init()
	{
	print "printing from a bro_init() event";
	}

event bro_done()
	{
	print "printing from a bro_done() event";
	}


print "printing outside any events or functions before the @-statements";
@if (T)
	@ifdef ( UniqueModuleName1234::foo )
		print fmt("printing from an @-statement. UniqueModuleName1234::foo is defined as: %s", UniqueModuleName1234::foo);
	@else
		print "@-statements are interpretted before export frames";
	@endif
@else 
	print "this should never happen, because the initial @if was set to T";
	# try setting the if statement to F and see what occurs
@endif
# why doesn't the following print statement print anything?
print "printing outside any events or functions after the @-statements";
