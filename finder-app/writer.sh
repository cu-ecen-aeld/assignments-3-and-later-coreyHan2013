#!/bin/bash

if [ $# = 0 ]; then
	echo "missing first parameter: writefile"
	echo "missing second parameter: writestr"
	exit 1
elif [ $# = 1 ]; then
	echo "missing second parameter: writestr"
	exit 1
fi

mkdir -p $(dirname $1) && touch $1
if [ $? -ne 0 ]; then
	echo "couldn't create file $1"
	exit 1
fi
echo $2 > $1

