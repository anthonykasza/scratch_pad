Track chains of related DNS and HTTP 
------------------------------------
this is useful for analyzing drive by compromises, but can also be used to troubleshoot HTTP redirects



try running
	bro -Ci eth0 chains.bro

then running
	wget google.com

the wget command will cause
- a dns request for google.com
- an http 
    - request to an IP with host: google.com
    - response stating host google.com is located at www.google.com
- a dns request for www.google.com
- an http request to an IP with host: www.google.com
