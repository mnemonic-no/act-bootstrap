#!/bin/sh

BOOTSTRAP_HOME=`dirname $0`

LOGLEVEL=info
USERID=$1
ACT_BASEURL=$2

FACT_TYPES=${BOOTSTRAP_HOME}/types/fact-types.json
META_FACT_TYPES=${BOOTSTRAP_HOME}/types/metafact-types.json
OBJECT_TYPES=${BOOTSTRAP_HOME}/types/object-types.json
LOG=bootstrap.log.$$

if [ "$ACT_BASEURL" = "" ]
then
    echo "syntax: bootstrap.sh <user id> <act baseurl>"
    echo "example: bootstrap.sh 1 http://localhost:8080"
    exit 1
fi

export PYTHONPATH=$PYTHONPATH:${BOOTSTRAP_HOME}/bootstrap

ARGS="--userid $USERID --act-baseurl $ACT_BASEURL --loglevel $LOGLEVEL --logfile $LOG"

echo "Logging to $LOG"

bootstrap/act-bootstrap.py $ARGS --object-types ${OBJECT_TYPES} --fact-types ${FACT_TYPES} --meta-fact-types ${META_FACT_TYPES}
bootstrap/misp-threat-actors.py $ARGS
bootstrap/fireeye-carbanak.py $ARGS
