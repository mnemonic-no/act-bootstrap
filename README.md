# ACT bootstrap

## Introduction

These scripts are used to bootstrap the [ACT](https://github.com/mnemonic-no/act-platform) data model (object types and fact types) and open sources, like mitre attack and threat actors from MISP galaxy.

## Requirements

* [python-act](https://github.com/mnemonic-no/python-act)

## Usage

To bootstrap only the types:

```
bootstrap/act-bootstrap.py \
    --userid 1 \
    --act-baseurl http://localhost:8080 \
    --loglevel ERROR \
    --object-types types/object-types.json \
    --fact-types datamodel/types/fact-types.json
```

To bootstrap the type system and all OSINT (using userID 1 and API server on localhost:8080):

```
./act-bootstrap.sh 1 http://localhost:8080
```
