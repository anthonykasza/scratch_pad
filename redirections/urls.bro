export {
	type uri: record {
		protocol:	string &optional;
		# this could be a domain name or an IP address
		netlocation:	string;
		portnum:	count &optional;
		path:		string &optional;
		file_name:	string &optional;
		file_ext:	string &optional;
	};

	global decompose_uri: function(s: string): uri;
}

function decompose_uri(s: string): uri
	{
	local parts: string_array;
	local u: uri = [$netlocation=""];

	if (/:\/\// in s)
		{
		parts = split1(s, /:\/\//);
		u$protocol = parts[1];
		s = parts[2];
		}
	if (/\// in s)
		{
		parts = split1(s, /\//);
		s = parts[1];
		u$path = fmt("/%s", parts[2]);
		
		if (|u$path| > 1)
			{
			local last_token: string = find_last(u$path, /\/.+/);
			local full_filename = split1(last_token, /\//)[2];
			if (/\./ in full_filename)
				{
				u$file_name = split1(full_filename, /\./)[1];
				u$file_ext = split1(full_filename, /\./)[2];
				u$path = subst_string(u$path, fmt("%s.%s", u$file_name, u$file_ext), "");
				}
			else
				{
				u$file_name = full_filename;
				u$path = subst_string(u$path, u$file_name, "");
				}
			}
		}
	if (/:/ in s)
		{
		parts = split1(s, /:/);
		u$netlocation = parts[1];
		u$portnum = to_count(parts[2]);
		}
	else
		{
		u$netlocation = s;
		}

	return u;
	}
