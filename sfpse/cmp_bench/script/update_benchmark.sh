#!/bin/bash 

base=10
num=5
result=1

for i in `seq 1 5`;
do
	result=$(($result * $base))
	for j in `seq 0 4`;
	do
		
		./sfpse_cmpbench -r $result -n $j -t u
	done

done
