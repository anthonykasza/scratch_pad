Indicator Rules
===============
Adding context and layering to intelligence indicators. This package is built on top of the Intel framework. See [here](http://www.bro.org/bro-exchange-2013/exercises/intel.html) for examples on using the intel framework.

Description
-----------
This package provides extensions for brogrammers to create complex conditional rules based on intelligence indicators. The ultimate goal of something like this would be a framework for context aware [yara](http://plusvic.github.io/yara)-like network rule sets. 

Usage
-----
- create indicators (or use the provided ones in indicators.dat)
- create rules based on the indicators (or use the ones provided)
	- rules can be read in from a file or added form scriptland similar to indicators
- run Bro on an interface
- cause network traffic that will match the indicators and conditions in your rules (or your rules' rules)
	- the included rules will match on 'wget www.google.com/foo' and 'wget www.google.com/bar' (depending on your version of wget)
- look in the notice.log file for Intel::Rule_Match notes

ToDo
----
- extend rules to support clustering (fraternities)
	- indicator metadata isn't distributed to workers, this could be problematic
- consider placing indicator "hits" in hidden value of connection types (similar to how everything else is just dumping into a new connection value)
	- opposed to keeping a single central table (indicator_cache)
	- let each connection carry it's own indicator matches around?
- support patterns in indicators
	- indicators as [substrings](http://www.bro.org/sphinx/scripts/base/bif/strings.bif.html#id-strstr) of meta.if_in value, not absolute value
	- this is most likely a rewrite to fully support patterns, not a simple add-on
- given indicators and rules are logically seperate, consider ways to shadow indicators while distributing rules
	- can indicators be hidden from worker nodes somehow?
