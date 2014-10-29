# Let's build a table of the data types and then print it
# then let's try to flatten everything in the table and then print it

module DataTypes;

export {
	global f_void: function();
	global f_string: function(): string; 
	global t1: table[string] of any;
	global ev: event();
	global h: hook();

	type rec: record {
		s: string;
		n: count;
		i: int;
	} &redef;

	type e: enum {LARGE, MEDIUM, SMALL,};
}

function f_void()
	{
	}

function f_string(): string
	{
	return "f_string_return_value!!!";
	}

event ev()
	{
	local n: count = 2+2;	
	}

hook h()
	{
	local s: string = "foo";
	}

event bro_init()
	{
	local n: count = 1;
	local i: int = -1;
	local s: string = "abc";
	local b: bool = F;
	local d: double = 1.111;
	local t: time = current_time();
	local I: interval = 3.5 mins;
	local p: pattern = /foo|bar/;
	local P: port = 53/udp;
	local a: addr = 10.0.0.1;
	local S: subnet = 10.0.0.1/8;
	local o: opaque of md5 = md5_hash_init(); md5_hash_update(o, "test");
	local f: file = open("foo.txt");
	local r: rec = [$s="s", $n=10, $i=-10];
	local en: e = LARGE;
#	local T: table = 	# table of what?
#	local ss: set = 	# set of what?
#	local v: vector = 	# vector of what?

	t1["count"] = n;
	t1["int"] = i;
	t1["string"] = s;
	t1["bool"] = b; 
	t1["double"] = d;
	t1["time"] = t;
	t1["interval"] = I;
	t1["pattern"] = p;
	t1["port"] = P;
	t1["addr"] = a;
	t1["subnet"] = S;
	t1["opaque"] = md5_hash_finish(o);
	t1["record"] = r;
	t1["file"] = f;
	t1["f_void_call"] = f_void();
	t1["f_void"] = f_void;
	t1["f_string_call"] = f_string();
	t1["f_string"] = f_string;
	t1["event"] = ev; 		# what's weird is that the variable contains (or just points to?) the contents of the event
#	t1["event_call"] = ev(); 	# this won't ever work. You cannot call an event from an expression. Only from a statement. The same goes for hooks.
#	t1["hook_call"] = h(); 		# this won't ever work. You cannot call an event from an expression. Only from a statement. The same goes for hooks.
	t1["hook"] = h;
#	t1["enum"] = en; 		# there is no printable version of an enum

	print t1;
	print "#########################";
	for (each in t1)
	{
		# ports have a strange flatten value...
		print fmt("%s = %d", each, |t1[each]|);
	}
	}
