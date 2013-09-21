# data type of opaque is a type with internal structure intentionally hidden
# opaque data types are of something
# e.g. local handle: opaque of md5 = md5_hash_init();

#global foo: opaque of 
#			md5
#			bloomfilter
#			sha1
#			sha256
#			entropy
#			topk
#			

## FOR SOME REASON EACH OF THESE CAUSES A SEG FAULT
##	Segmentation fault (core dumped)

#bloomfilter_basic_init(fp: double, capacity: count, name: string &default = "" &optional)
global my_bloom: opaque of bloomfilter = bloomfilter_basic_init(0.1, 10, "my_bloomfilter_name");

#bloomfilter_basic_init2(k: count, cells: count, name: string &default = "" &optional)
global my_bloom2: opaque of bloomfilter = bloomfilter_basic_init2(3, 25, "my_bloomfilter2_name");

#bloomfilter_counting_init(k: count, cells: count, max: count, name: string &default = "" &optional)
global my_counting_bloom = bloomfilter_counting_init(3, 10, 25, "my_coutning_bloom");
