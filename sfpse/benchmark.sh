#!/bin/bash 

base=10
num=5
result=100

./sfpse_cmpbench -r 600 -n 2 -t u
#for i in `seq 3 6`;
#do
#	result=$(($result * $base))
#	for j in `seq 0 4`;
#	do
		
#		./sfpse_cmpbench -r $result -n $j -t u
#		./sfpse_cmpbench -r $result -n $j -t s
#	done

#done
