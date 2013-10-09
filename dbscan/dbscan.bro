module DBscan;
export {
	type Point: record {
        	x:      double;
        	y:      double;
	} &redef;
}

redef record Point += {
	# noise is labeled as 0
	lbl:		count &optional;
	visited:    	bool &default = F;
	neighbors:  	set[Point] &optional;
};

function regionQuery(d: set[Point], p: Point, eps: double): set[Point]
{
    local n: set[Point];
    for (each in d)
    {
        local a: double = |each$x - p$x|;
        local b: double = |each$y - p$y|;

        if ( ((a*a)+(b*b)) <= sqrt(eps) )
        {
            add n[each];
        }
    }
    return n;
}

function expandCluster(d: set[Point], p: Point, cluster: count, eps: double, minpts: count)
{
        p$lbl = cluster;
        for (np in p$neighbors)
        {
                if (d[np$visited] = F)
                {
                        d[np$visited] = T;
                        d[np$neighbors] = regionQuery(d, np, eps);
                        if (d[np$neighbors] >= minpts)
                        {
                                for (each in d[np$neighbors])
                                {
                                        add p$neighbors[each];
                                }
                        }
                }
                if ( (! d[np?$lbl]) || (d[np$lbl]=0) )
                {
                        d[np]$lbl = cluster;
                }
        }
}

function dbscan(d: set[Point], eps: double, minpts: count): set[Point]
{
	local cluster: count = 0;
	for (p in d)
	{
		if (! p$visited) 
		{
			p$visited = T;
			p$neighbors = regionQuery(d, p, eps);
		       
			if ( (p?$neighbors) && (|p$neighbors| < minpts) )
			{
				# mark the point as noise
				p$lbl = 0;
			} else {
				cluster += 1;
			#	expandCluster(d, p, cluster, eps, minpts);
			}
		}
		print d;
	}
	return d;
}

global data: set[Point] = {[$x=1.0, $y=1.0], [$x=1.0, $y=2.0], [$x=2.0, $y=1.0], [$x=2.0, $y=2.0], [$x=10.0, $y=10.0]};
#print data;
#print regionQuery(data, [$x=1.0, $y=1.0], 2.0);

dbscan(data, 2.0, 2);

