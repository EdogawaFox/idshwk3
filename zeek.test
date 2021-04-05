global ip_to_useragent: table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{

	if (to_lower(name) == "user-agent")
	{
		if (c$id$orig_h !in ip_to_useragent)
		{
			ip_to_useragent[c$id$orig_h] = set(value);
		}
		
		add ip_to_useragent[c$id$orig_h][value];
	
	}

}

event zeek_done()
{
	for ( i in ip_to_useragent)
	{
		if (|ip_to_useragent[i]| >= 3)
		{
			print fmt("%s is a proxy", i);
		}
	}
}
