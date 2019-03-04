#!/bin/sh

### Sort json files

for file in $(ls -1 *json)
do
    TMP="${file}.tmp"
    echo $file
    # `ls -1`
    jq -S 'sort_by(.name)' $file > $TMP

    if [ "$?" = "0" ] # No error?
    then
        mv $TMP $file
    fi
done
