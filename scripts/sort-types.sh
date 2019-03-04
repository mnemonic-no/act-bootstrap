#!/bin/sh
set -e

# Iterate over JSON files in types directory and sort them
for file in `ls -1 ../types/*.json`; do
    TMP="${file}.tmp"
    jq -S 'sort_by(.name)' $file > $TMP

    # If no error was returned from sorting
    if [[ "$?" = "0" ]]; then
        echo "sucessfully sorted ${file}"
        mv $TMP $file
    else
        echo "error occured during sort of ${file}"
        rm $TMP
    fi
done
