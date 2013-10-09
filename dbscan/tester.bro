type Ctype: record {
	c: count;
};

global g: set[Ctype] = set([$c=1], [$c=1], [$c=1], [$c=1], [$c=1], [$c=1], [$c=1]);
print g;

for (each in g)
{
	print each;
	each$c += 1;
	print each;
}

print g;
