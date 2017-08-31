#!/bin/bash 

base=10
num=5
result=1000

for i in `seq 5 6`;
do
	result=$(($result * $base))
	for j in `seq 0 4`;
	do
		
		./sophos_cmpbench -r $result -n $j -t s
	done

done

