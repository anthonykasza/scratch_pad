# load the package
@load ./rules

# read in an intel file for indicators
redef Intel::read_files += {
        fmt ("%s/indicators.dat", @DIR)
};

# create rules with the add_rule function
Intel::add_rule( [$rid="RID_1", $i_condition=Intel::AND, $iids=set("IID_1", "IID_2", "IID_3", "IID_5", "IID_999")] );
Intel::add_rule( [$rid="RID_2", $i_condition=Intel::AND, $iids=set("IID_1", "IID_4")] );
Intel::add_rule( [$rid="RID_3", $i_condition=Intel::OR,  $iids=set("IID_5")] );
Intel::add_rule( [$rid="RID_4", $iids=set("IID_2", "IID_3")] );

