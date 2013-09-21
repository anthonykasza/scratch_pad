## Monitor HTTP requests for a specific set of unordered parameters 
#
# 	RFC 3986 reserved URI characters (must be encoded if not used as delims)
#		: / ? # [ ] @
#		! $ & ' ( ) * + , ; =

module HTTP;

export {
	type ss_t: record {
		params: set[string];
	};

	global parameters: table[ss_t] of string;
}

event bro_init()
{
	parameters [ [$params = set("one", "two", "three")] ] = "numbers_spelled_out";
	parameters [ [$params = set("foo", "bar")] ] = "foo_AND_bar";
	parameters [ [$params = set("foo", "bar", "baz")] ] = "foo_AND_bar_AND_baz";
}

function extract_params(uri: string): set[string]
{
	local p: set[string] = set();

	if ( strstr(uri, "?") == 0)
		return p;

	local query: string = split1(uri, /\?/)[2];
	local opv: table[count] of string = split(query, /&/);
	
	# This function could easily be altered to keep order of parameter occurance by 
	# altering the return type of the function and returning opv here
	#return opv;

	for (each in opv)
	{
		add p[ split1(opv[each], /=/)[1] ];
	}
	return p;
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	local ss: set[string] = extract_params(original_URI);
	
	if ([$params=ss] in parameters)
		print parameters[ [$params=ss] ];
}
