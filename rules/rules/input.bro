@load ./main

# copied and repurposed from base/frameworks/intel/input.bro

module Intel;

export {
	## Intelligence rules files that will be read off disk.  The files are
	## reread every time they are updated so updates must be atomic with
	## "mv" instead of writing the file in place.
	const read_rules_files: set[string] = {} &redef;
}

event Intel::read_rule_entry(desc: Input::EventDescription, tpe: Input::Event, r: Intel::Rule)
	{
	Intel::add_rule(r);
	}

event bro_init() &priority=5
	{
	if ( ! Cluster::is_enabled() ||
	     Cluster::local_node_type() == Cluster::MANAGER )
		{
		for ( a_file in read_rules_files )
			{
			Input::add_event([$source=a_file,
			                  $reader=Input::READER_ASCII,
			                  $mode=Input::REREAD,
			                  $name=cat("intel_rules-", a_file),
			                  $fields=Intel::Rule,
			                  $ev=Intel::read_rule_entry]);
			}
		}
	}

