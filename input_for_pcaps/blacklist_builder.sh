echo -e "#fields\tip\ttimestamp\treason"

for i in {1..1}; do
	for j in {1..5}; do
		for k in {1..255}; do
			for l in {1..255}; do
				echo -e "$i.$j.$k.$l\t1324567890\tbadIP"
			done
		done
	done
done
