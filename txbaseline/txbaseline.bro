@load base/frameworks/notice
@load base/frameworks/sumstats

redef use_conn_size_analyzer = T;

module TxBaseline;
export {
#        redef enum Notice::Type += {
#                Too_much,
#                Too_little,
#        };

        # alter these intervals from minutess to days
        const tx_summer_interval = 1mins &redef;
        const tx_aver_interval = 7mins &redef;

        const week: vector of string = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"};
        global day_of_week: count = 6;
        global week_of_year: count = 0;

#        const tx_threshold = 0.0 &redef;
}


event bro_init() &priority=5
{
        local r1: SumStats::Reducer = [$stream="tx_summer", $apply=set(SumStats::SUM)];
        local r2: SumStats::Reducer = [$stream="tx_aver", $apply=set(SumStats::AVERAGE)];
#        local r3: SumStats::Reducer = [$stream="tx_stder", $apply=set(SumStats::STD_DEV)];

        SumStats::create( [$name="tx_aver",
                                $epoch=tx_aver_interval,
                                $reducers=set(r2),
                                $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                        local r = result["tx_aver"];
                                        print fmt("%s sent a weekly average of %f bytes. It is week %d", key$host, r$average, week_of_year);
                                },
                                $epoch_finished(ts: time) = 
                                {
                                        if (TxBaseline::week_of_year == 52)
                                        {
                                                TxBaseline::week_of_year = 0;
                                                return;
                                        }
                                        TxBaseline::week_of_year += 1;
                                }
                        ] );

        SumStats::create( [$name="tx_summer", 
                                $epoch=tx_summer_interval, 
                                $reducers=set(r1),
                                $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                        local r = result["tx_summer"];
                                        print fmt("%s sent a sum of %f bytes. Today is %s", key$host, r$sum, week[day_of_week] );
                                        SumStats::observe( "tx_aver", [$host=key$host], [$dbl=r$sum] );
                                },
                                $epoch_finished(ts: time) = 
                                {
                                        if (TxBaseline::day_of_week == 6) 
                                        {
                                                TxBaseline::day_of_week = 0;
                                                return;
                                        }
                                        TxBaseline::day_of_week += 1;
                                }
                        ] );
}

event connection_state_remove(c: connection)
{
        SumStats::observe( "tx_summer", [$host=c$id$orig_h], [$num=c$orig$num_bytes_ip] );
}

