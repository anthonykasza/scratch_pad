module Intel;
export {

	redef enum Notice::Type += { Intel::Rule_Notice };

	# a condition to apply to multiple indicators/items
	type Condition: enum {
		# At least one of the indicators were seen
		OR,
		# All the indicators were seen
		AND,
		# None of the indicators were seen
			# CAUTION: USE AT YOUR OWN RISK
			# creating rules with a condition of NONE has the potentional to match many things, store a lot of state, and generate many notices
		NONE,
		# Exactly one of the indicators were seen
		XOR,
	};

	type Rule: record  {
		# condition to apply to included indicators
		i_condition:	Condition &default=OR;
		# set of indicators to monitor for
		iids:		set[string] &default=set();
		# rule identification string
		rid:		string;
		# set of rules to monitor for
		rids:		set[string] &default=set();
		# condition to apply to included rules
		r_condition:	Condition &default=OR;
		# do you want to get notices about this rule firing?
        	do_rules_notice: bool &default=F;
	};

	redef record Intel::MetaData += {
		# indicator identification string
		iid: 	string &optional;
	};

	# interface to add rules to check for
	# to update a rule, simply re-add it
	global add_rule: function(r: Rule);

	# interface to remove rules
	global delete_rule: function(r: Rule);
}

# Rule indxed by rid, rid=>[Rule]
global indicator_rules: table[string] of Rule &redef;

# set of indicators indexed by connection UID, uid=>[iid, iid, iid]
global indicator_cache: table[string] of set[string] &redef;

function add_rule(r: Intel::Rule)
{
	Intel::indicator_rules[r$rid] = r;
}

function delete_rule(r: Intel::Rule)
{
	delete Intel::indicator_rules[r$rid];
}

event Intel::match(s: Seen, items: set[Item]) &priority=-2
{
	for (each_item in items)
	{
		if (! each_item$meta?$if_in || s$where == each_item$meta$if_in)
		{
			# consider indexing items in the Intel::indicator_cache by something other than connection UID. perhaps by host?
			if (s$conn$uid in Intel::indicator_cache)
			{
				add Intel::indicator_cache[s$conn$uid][each_item$meta$iid];
			} else {
				Intel::indicator_cache[s$conn$uid] = set(each_item$meta$iid);
			}
		}
	}
}

# given a connection and a rule, check if the connection matches the rule's indicators and condition
function Intel::check_indicator_logic(r: Rule, c: connection): bool
{
	switch (r$i_condition)
	{
		case OR:
		for (each_iid in r$iids)
		{
			if (each_iid in indicator_cache[c$uid])
			{
				return T;
				break;
			}
		}
		break;

		case AND:
		local state: bool = F;
		for (each_iid in r$iids)
		{
			if (each_iid !in indicator_cache[c$uid])
			{
				state = F;
				break;
			} else {
				state = T;
				break;
			}
		}
		if (state)
		{
			return T;
		}
		break;

		case NONE:
		local none_iid_match: bool = T;
		for (each_iid in r$iids)
		{
			if (each_iid in indicator_cache[c$uid])
			{
				none_iid_match = F;
				break;
			}
		}
		if (none_iid_match)
		{
			return T;
		}
		break;

		case XOR:
		local one_iid_match: bool = F;
		for (each_iid in r$iids)
		{
			if (each_iid in indicator_cache[c$uid])
			{
				if (one_iid_match)
				{
					one_iid_match = F;
					break;
				}
				one_iid_match = T;
			}
		}
		if (one_iid_match)
		{
			return T;
		}
		break;

	}

	return F;
}

# given a connection and a nested rule, check if the connection matches the rule's rules and condition
function Intel::check_rule_logic(r: Rule, c: connection): bool
{

	switch (r$r_condition)
	{
		case OR:
		for (each_rid in r$rids)
		{
			if ( check_indicator_logic(indicator_rules[each_rid], c) )
			{
				return T;
				break;
			}
		}
		break;

		case AND:
		local state: bool = F;
		for (each_rid in r$rids)
		{
			if (! check_indicator_logic(indicator_rules[each_rid], c) )
			{
				state = F;
				break;
			}
			else
			{
				state = T;
			}
		}
		if (state)
		{
			return T;
		}
		break;

		case NONE:
		local none_rid_match: bool = T;
		for (each_rid in r$rids)
		{
			if ( check_indicator_logic(indicator_rules[each_rid], c) )
			{
				none_rid_match = F;
				break;
			}
		}
		if (none_rid_match)
		{
			return T;
		}
		break;

		case XOR:
		local one_rid_match: bool = F;
		for (each_rid in r$rids)
		{
			if ( check_indicator_logic(indicator_rules[each_rid], c) )
			{
				if (one_rid_match)
				{
					one_rid_match = F;
					break;
				}
				one_rid_match = T;
			}
		}
		if (one_rid_match)
		{
			return T;
		}
		break;

	}

	return F;

}

event connection_state_remove(c: connection)
{
	if (c$uid !in Intel::indicator_cache) return;

	for (r in Intel::indicator_rules)
	{
		# If the rule consists of a set of indicators and no nested rules
		if ( (|Intel::indicator_rules[r]$rids| == 0) && (|Intel::indicator_rules[r]$iids| > 0) )
		{
			# check it's indicator logic and notice
			if ( check_indicator_logic(Intel::indicator_rules[r], c) )
			{
				if (Intel::indicator_rules[r]$do_rules_notice) NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", Intel::indicator_rules[r]$rid)] );
			}
		}

		# If the rule consists of nested rules and no indicators
		else if ( (|Intel::indicator_rules[r]$rids| > 0) && (|Intel::indicator_rules[r]$iids| == 0) )
		{
			# check it's rule logic and notice
			if ( check_rule_logic(Intel::indicator_rules[r], c) )
			{
				if (Intel::indicator_rules[r]$do_rules_notice) NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", Intel::indicator_rules[r]$rid)] );
			}
		}

		# If the rule consists of nested rules and indicators
		else if ( (|Intel::indicator_rules[r]$rids| > 0) && (|Intel::indicator_rules[r]$iids| > 0) )
		{
			# check it's indicator logic and it's rule logic, then notice
			if ( (check_indicator_logic(Intel::indicator_rules[r], c)) && (check_rule_logic(Intel::indicator_rules[r], c)) )
			{
				if (Intel::indicator_rules[r]$do_rules_notice) NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", Intel::indicator_rules[r]$rid)] );
			}
		}

		# If the rule consists of no nested rules and no indicators
		else
		{
			# there's nothing to do and keeping the rule is a waste
			Intel::delete_rule(Intel::indicator_rules[r]);
		}

	}

	# when a connection expires, so do all the Intel::match hits that went with it
	delete Intel::indicator_cache[c$uid];
}
