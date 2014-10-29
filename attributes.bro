# attributes... see here <https://www.bro.org/sphinx-git/script-reference/attributes.html>
# The following attributes are deprecated
#       &rotate_interval
#       &rotate_size
#	&mergable
#	&synchronized
#	&persistent
#	&group
#
# The following attributes are used internally only
#	&type_column
#	&error_handler
# 
# The following attribute seems to make Bro halt unexpectedly
#	&encrypt
#		bro -Ci eth0 -e 'global f1: file = open("out1.log") &encrypt;

module GLOBAL;
export {
	global string_printer: function(s1: string, s2: string): string;

	# &add_func likely wasn't designed with strings use in mind and 
	# was likely intended for use with enums and records
	# because strings don't have a -= operator, we cannot set a &delete_func
	const gab: string = "gab" &redef &add_func=string_printer; 
}

function string_printer(s1: string, s2: string): string
	{
	print fmt("s1: %s, s2: %s", s1, s2);
	return s1 + s2;
	}

event bro_init() &priority=-10
	{
	print fmt("printing from GLOBAL space: %s", gab);
	}

##################################################################################

module Attributes;
export {
	global my_expire: function(tos: table[string] of string, s: string): interval;

	redef gab += "s"; 
	global baz: function(s: string &default="DEFAULT VALUE");

	global bar: table[string] of string &create_expire=0secs &expire_func=Attributes::my_expire;
}

event bro_init() &priority=0
	{
	Attributes::baz();
	Attributes::baz(gab);
	}

event bro_init() &priority=10
	{
	Attributes::bar["a"] = "1";
	Attributes::bar["b"] = "2";
	Attributes::bar["c"] = "3";
	print Attributes::bar;
	}

function Attributes::baz(s: string &default="DEFAULT VALUE")
	{
	print fmt ("printing from Attributes space: %s", s);
	}

function Attributes::my_expire(tos: table[string] of string, s: string): interval
	{
	print fmt("the size of our table is %d", |tos|);

	if (s == "a") {
		print fmt("printing from my_expire, handling %s", s);
		return 0secs;
	} else if ( s == "b") {
		print fmt("printing from my_expire, handling %s", s);
		return 10secs;
	} else {
		print fmt("printing from my_expire, handling %s", s);
		return 0secs;
	}
	}

##################################################################################

module FileThings;
export {
	global print_something: event(fh: file, s: string, i: interval &default=0secs);

        global f1: file = open("out1.log") &raw_output;
#        global f2: file = open("out2.log") &encrypt;

}

event FileThings::print_something(fh: file, s: string, i: interval &default=0secs)
	{
	# print some string to some file and schedule it to happen again
	print fh, s;
	schedule i { FileThings::print_something(fh, s, i) };
	}

event bro_init()
	{
        schedule 0secs { FileThings::print_something(f1, "foo", 1secs) };
	}

event bro_done()
	{
        close(f1);
	}
