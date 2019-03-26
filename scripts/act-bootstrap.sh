#!/bin/sh

set -e

log() {
    echo "`date` [BOOTSTRAP] $1"
}

usage() {
    echo ""
    echo "syntax: bootstrap.sh <user id> <act baseurl>"
    echo "example: bootstrap.sh 1 http://localhost:8888"
}

BOOTSTRAP_HOME=`dirname $0`/..
USERID=$1
ACT_BASEURL=$2
LOGLEVEL=info
LOGDIR=${BOOTSTRAP_HOME}/log
LOGFILE=${LOGDIR}/bootstrap.log.`date +%s`
FACT_TYPES=${BOOTSTRAP_HOME}/types/fact-types.json
META_FACT_TYPES=${BOOTSTRAP_HOME}/types/metafact-types.json
OBJECT_TYPES=${BOOTSTRAP_HOME}/types/object-types.json

if [ ! -d "$LOGDIR" ]; then
    log "Created log directory $LOGDIR"
    mkdir ${LOGDIR}
fi

if [ "$USERID" == "" ]; then
    log "Please supply an ACT user id"
    usage
    exit 1
fi

if [ "$ACT_BASEURL" == "" ]; then
    log "Please supply an ACT base url"
    usage
    exit 1
fi

export PYTHONPATH=$PYTHONPATH:${BOOTSTRAP_HOME}/bootstrap

ARGS="--userid $USERID --act-baseurl $ACT_BASEURL --loglevel $LOGLEVEL --logfile $LOGFILE"

log "Starting bootstrap process, logging to $LOGFILE"
bootstrap/act-bootstrap.py $ARGS --object-types ${OBJECT_TYPES} --fact-types ${FACT_TYPES} --meta-fact-types ${META_FACT_TYPES}
bootstrap/misp-threat-actors.py $ARGS
bootstrap/fireeye-carbanak.py --md5-lookup data/carbanak_md5_sha256.txt $ARGS
log "Bootstraping completed"
