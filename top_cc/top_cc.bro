module TopCC;
 
export {
        # how many countries to count in topX
        global top_cc_count: count = 10;
 
        # the topk object used to track everything
        global top_cc: opaque of topk = topk_init( top_cc_count );
 
        # how frequenty we should check for new connections and redraw graph
        global draw_freq: interval = 5secs;
 
        # internal counter used to check if topk object has new connection (thus causing a redraw)
        global top_cc_sum: count = 0;
}
 
event draw()
{
        # each draw() event schedules the next draw() event
        schedule draw_freq { draw() };
 
        if (topk_sum(top_cc) == top_cc_sum)
                return;
 
        local c_list: vector of string = topk_get_top(TopCC::top_cc, top_cc_count);
 
        print "=============================================================";
        for (each in c_list)
        {
                local tkc: count = topk_count(top_cc, c_list[each]);
                print fmt("%s: %s", c_list[each], sub( string_fill( tkc+1, "*"), /\0/, "") );
        }
 
        top_cc_sum = topk_sum(top_cc);
}
 
event bro_init()
{
        # schedule the first draw()
        schedule draw_freq { draw() };
}
 
event new_connection(c: connection)
{
        if ( c?$id && c$id?$resp_h )
        {
                local g: geo_location = lookup_location(c$id$resp_h);
                if (g?$country_code)
                {
                        topk_add(TopCC::top_cc, g$country_code);
                }
        }
 
}
 
event bro_done()
{
        local c_list: vector of string = topk_get_top(TopCC::top_cc, top_cc_count);
        for (each in c_list)
        {
                print fmt("%s => %d", c_list[each], topk_count(top_cc, c_list[each]) );
        }
 
        print topk_sum(top_cc);
}
