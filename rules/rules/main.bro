module Intel;
export {

	redef enum Notice::Type += { Intel::Rule_Notice };

	# a condition to apply to multiple indicators/items
	type Condition: enum {
		OR,
		AND,
	};

	type Rule: record  {
		# condition to apply to included indicators
		i_condition:	Condition &default=OR;

		# set of indicators to monitor for
		iids:		set[string];

		# rule identification string
		rid:		string;
	};

# nested rules aren't supported yet
#
#	redef record Rule += {
#		rules:		set[Rule];
#		r_condition:	Condition &default=OR;
#	};
#
	redef record Intel::MetaData += {
		# indicator identification string
		iid: 	string &optional;
	};

	# interface to add rules to check for
	global add_rule: function(r: Rule);
}

global indicator_rules: set[Rule];

global indicator_cache: table[string] of set[string];

function add_rule(r: Intel::Rule)
{
	add Intel::indicator_rules[r];
}

event Intel::match(s: Seen, items: set[Item]) &priority=-2
{
	for (each_item in items)
	{
	# does it make sense to key on conn$uid?
	# would it make more sense to key on conn$id$orig_h?
		if (s$conn$uid in Intel::indicator_cache)
		{
			add Intel::indicator_cache[s$conn$uid][each_item$meta$iid];
		} else {
			Intel::indicator_cache[s$conn$uid] = set(each_item$meta$iid);
		}
	}
}

event connection_state_remove(c: connection)
{
	if (c$uid !in Intel::indicator_cache) return;

	for (each_rule in Intel::indicator_rules)
	{	
		switch ( each_rule$i_condition)
		{
			case OR:
			for (each_iid in each_rule$iids)
			{
				if (each_iid in indicator_cache[c$uid])
				{
					NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", each_rule$rid)] );
					break;
				}
			}
			break;

			case AND:
			for (each_iid in each_rule$iids)
			{
				if (each_iid !in indicator_cache[c$uid])
				{
					break;
				} else {
					NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", each_rule$rid)] );
					break;
				}
			}
			break;
		}
	}

	# when a connection expires, so do all the Intel::match hits that went with it
	delete Intel::indicator_cache[c$uid];
}
