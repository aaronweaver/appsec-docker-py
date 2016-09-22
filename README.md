# Description
Docker utility to launch security tools

Installation
------------

    pip install docker-py

Example
------------

Running against a local docker install and launching arachni.

    python docker-run.py --tool arachni --build build_55 --host local  

Running against a remote docker and launching zap.

    export dockercert='path/to/cert.pem'
    export dockerkey='path/to/key.pem'

    python docker-run.py --tool arachni --build test02 --host tcp://yourhost:2376
