#!/bin/bash

## declare an array variable
declare -a arr=("acl-table.hpp" "acl-table.cpp" "arp-cache.cpp" "routing-table.cpp" "simple-router.hpp" "simple-router.cpp" "ATABLE")

# now loop through the above array
for i in "${arr[@]}"
do
    sudo docker cp "$i" "08bdd989bba2:/$i"
   # or do whatever with individual element of the array
done

    sudo docker cp core/protocol.hpp 08bdd989bba2:/core/protocol.hpp

# You can access them using echo "${arr[0]}", "${arr[1]}" also




