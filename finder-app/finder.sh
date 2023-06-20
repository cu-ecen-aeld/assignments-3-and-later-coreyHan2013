#!/bin/bash

if [ $# = 0 ]; then
	echo "missing first parameter: filesdir"
	echo "missing second parameter: searchstr"
	exit 1
elif [ $# = 1 ]; then
	echo "missing second parameter: searchstr"
	exit 1
fi

if [ ! -d $1 ]; then
	echo "$1 doest not exist"
	exit 1
fi

FILE_NO=`grep -d recurse -l $2 $1/* | wc -l`
LINE_NO=`grep -d recurse -o $2 $1/* | wc -l`
echo "The number of files are $FILE_NO and the number of matching lines are $LINE_NO"

