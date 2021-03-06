# load the rules package
@load ./rules

# read in an intel file for indicators
redef Intel::read_files += {
        fmt ("%s/indicators.dat", @DIR)
};

# read in rules file for applying logic based on indicators
redef Intel::read_rules_files += {
	fmt ("%s/rules.dat", @DIR)
};

# rules can also be created in scriptland by calling the Intel::add_rule function
#Intel::add_rule( [$rid="RID_1", $i_condition=Intel::AND, $iids=set("IID_1", "IID_5")] );
#Intel::add_rule( [$rid="RID_2", $i_condition=Intel::OR, $iids=set("IID_6", "IID_7")] );
#Intel::add_rule( [$rid="RID_3", $r_condition=Intel::AND,  $rids=set("RID_1","RID_2")] );

