##! This is a basic Bro script that uses HTTP requests seen by Bro to print something to STDOUT
##! Printing to STOUT is generally not done (use notices instead). This program is intended for instructional uses only.
##! To use this program, ensure Bro sees an HTTP reuqest with a URI consisting of multiple levels ('/').

# This is a function declaration. The name of the function is greeting. The function has a single parameter.
# The name of the parameter is name and the type of the parameter is string.
# The colon after the closing parenthesis followed by the word string indicates the function is defined to return a string.
function greeting(name: string): string
{
	# This function concatenates the string passed to it with static strings and returns the results
        return "Hello, " + name + " you smell of elderberries";
}

# Below is an event handler. This is a block of code that will execute when Bro witnesses an HTTP request.
# More information about this, and other events types Bro has built in by default can be found here:
#	http://www.bro.org/documentation/scripts/base/event.bif.html
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	# This is an if statement. This if statement checks the contents of a string named method.
	# method contains the HTTP method used in the HTTP request which raised this event. 
	# Bro handles passing the proper values to events for the programmer.
	# Given that the HTTP request which raised this event does not use the GET verb, this block of code will no do anything
        if (method != "GET")
		# Bro follows conventions of other languages in that the line following an if statement is executed if
		# the statement is true. To execute more than one line of code after an if statement, place the code
		# in curly brackets {}
                return;
	# At this point in the HTTP request event, the greeting function is invoked and the unescaped URI from the HTTP 
	# request is passed to it. The returned results are then printed to STDOUT.
        print greeting(unescaped_URI);

	# This is a local variable declaration. The variable named path of type string_array is set to equal the 
	# returned value of the split function. 
	# The split function is passed the value returned from the strip function.
	# The strip function is passed a string, the unesacped_URI variable, and a patern to split the string on.
	# Variables of type pattern hold regular expressions.
	# More information on pattern type variables in Bro can be found here:
	#	http://www.bro.org/documentation/scripts/builtins.html#type-pattern
	# More information on string manipulation functions in Bro can be found here:
	#	http://www.bro.org/documentation/scripts/base/strings.bif.html
        local path: string_array = split( strip(unescaped_URI), /\// );

	# This is an invocation of a for loop.
	# The variable p is set to each index of the string array named path and the block of code below is then executed
	# For loops, such as this one, do not consider the index of the variable being iterated over. Order is never guaranteed when 
	# iterating complex Bro data structures.
	# See subexercise part 4 from the 2011 Bro workshop for an additional example of this:
	#	http://www.bro.org/bro-workshop-2011/solutions/prog-primer/part1.bro
	# Because of this, loops must be used carefully 
        for (p in path){
		# As p is set only to an index, we must use it so.
		# This if statement checks to see if each string in the string array path equals an empty string.
                if (path[p] == "")
			# If the condition is true, the current iteration of the loop is ended.
                        next;
		# The value of each index of the string array is printed to STOUT.
                print (path[p]);
        }
}

