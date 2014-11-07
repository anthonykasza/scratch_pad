try running
	bro -Ci eth0 chains.bro

then running
	wget google.com

the wget command will cause
1. a dns request for google.com
2. an http 
	a. request to an IP with host: google.com
	b. response stating host google.com is located at www.google.com
4. a dns request for www.google.com
5. an http request to an IP with host: www.google.com
