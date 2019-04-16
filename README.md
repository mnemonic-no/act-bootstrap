# # DEPRECATED (ACT bootstrap)

This repository is deprecated. Type functionality is moved to [act-types](https://github.com/mnemonic-no/act-types) and a python package is now avilable on ([pypi](https://pypi.org/project/act-types/).

## Introduction

These scripts are used to bootstrap the [ACT](https://github.com/mnemonic-no/act-platform) data model (object types and fact types) and open sources, like mitre attack and threat actors from MISP galaxy.

## Installation
1. This project requires that you have a running installation of the [act-platform](https://github.com/mnemonic-no/act-platform).
2. To install the requirements and get this project running perform the following:
```
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

## Usage
To bootstrap the type system and all OSINT (using userID 1 and API server on localhost:8888:
```
./scripts/act-bootstrap.sh 1 http://localhost:8888
```

To bootstrap only the types:
```
bootstrap/act-bootstrap.py \
    --userid 1 \
    --act-baseurl http://localhost:8888 \
    --loglevel ERROR \
    --object-types types/object-types.json \
    --fact-types types/fact-types.json \
    --meta-fact-types types/metafact-types.json
```
