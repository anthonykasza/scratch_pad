# opaques
#local handle: opaque of md5 = md5_hash_init();
#md5_hash_update(handle, "test");
#md5_hash_update(handle, "testing");
#print md5_hash_finish(handle);







# hooks
#global myhook: hook(s: string);
#
#hook myhook(s: string) &priority=10
#{
#	print "priority 10 myhook handler", s;
#	s = "bye";
#}
#
#hook myhook(s: string)
#{
#	print "break out of myhook handling", s;
#	break;
#}
#
#hook myhook(s: string) &priority=-5
#{
#	print "not going to happen", s;
#}
#
#if ( hook myhook("hi") )
#{
#	print "all handlers ran";
#}
