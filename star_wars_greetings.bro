# inspired by chapter 7 of O'Reilly's Intermediate Perl
# no need to specify an interface when running this script

# declar a new type 'greeting' of base type function
type greeting: function(name: string): string;

# define all characters in the plot
global characters: set[string] = {
	"Han Brolo",
	"Broba Fett",
	"Admiral Ackbro",
	"C3PBro",
};

# declare the room all characters will enter into
global room: set[string] = {};

# define a table containing a greeting type for each character
global greets: table[string] of greeting = {
	["Han Brolo"]	= function(name: string): string
		{ 
			if (name == "Admiral Ackbro")
			{
				return "Han Brolo: It's not a trap, Ackbro.";
			} else if (name == "Broba Fett")
			{
				return "Han Brolo: Taste my laser, Fett.";
			} else
			{
				return fmt("Han Brolo: Heya, %s", name);
			}
		},
	["Broba Fett"]	= function(name: string): string 
		{
			if (name == "Admiral Ackbro")
			{
				return "Broba Fett: It's not a trap, Ackbro.";
			} else if (name == "Han Brolo")
			{
				return fmt ("Broba Fett: How's that carbon freeze, %s?", name);
			} else
			{
				return "Broba Fett: ...";
			}
		},
	["Admiral Ackbro"]= function(name: string): string 
		{
			return "Admir Ackbro: It's a TRAP!";
		},
	["C3PBro"]	= function(name: string): string 
		{
			return fmt("C3PBro: Greetings, %s", name);
		},
};

# have each character enter the room and greet one another
for (person_entering in characters)
{
	print "";
	print fmt("%s enters the room.", person_entering);
	
	for (person_there in room)
	{
		print greets[person_entering](person_there);
		print greets[person_there](person_entering);
	}

	add room[person_entering];
}
