#!/bin/sh
set -e

BOOTSTRAP_HOME=`dirname $0`/..

# Iterate over JSON files in types directory and sort them
for file in `ls -1 ${BOOTSTRAP_HOME}/types/*.json`; do
    basename_json=$(basename ${file})
    TMP="${basename_json}.tmp"
    jq -S 'sort_by(.name)' $file > $TMP

    # If no error was returned from sorting
    if [ "$?" = "0" ]; then
        echo "sucessfully sorted ${basename_json}"
        mv $TMP $file
    else
        echo "error occured during sort of ${basename_json}"
        rm $TMP
    fi
done
