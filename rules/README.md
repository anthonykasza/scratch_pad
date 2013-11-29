Indicator Rules
===============
Adding context and layering to intelligence indicators. This package is built on top of the Intel framework. See [here](http://www.bro.org/bro-exchange-2013/exercises/intel.html) for examples on using the intel framework.

Description
-----------
This package provides extensions for brogrammers to create complex conditional rules based on intelligence indicators. The ultimate goal of something like this would be a framework for context aware (yara)[http://plusvic.github.io/yara]-like network rule sets.

Usage
-----
- create indicators (or use the provided ones in indicators.dat)
- create rules based on the indicators (or use the ones provided)
	- rules can be read in from a file or added form scriptland similar to indicators
- run Bro on an interface
- cause network traffic that will match the indicators and conditions in your rules
- look in the notice.log file for Intel::Rule_Match notes

ToDo
----
- extend rules to include nested rules
- extend rules to support clustering (fraternities)
	- indicator metadata isn't distributed to workers, this could be problematic
- considering keying the indicator_cache on values other than connection uids
	- what about on end point addresses similar to how Intel items can be keyed on a string or an addr?
- extend the package to include a custom log file
	- currently everything is dropped into notices (maybe this is a good thing?)
- consider moving 'rules' its own framework instead of building it into the intel framework
