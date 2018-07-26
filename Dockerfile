FROM ubuntu:xenial

RUN mkdir checkpot
COPY ./ checkpot/

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y python3-dev python3-pip mercurial nmap docker.io

RUN pip3 install --upgrade pip
RUN pip3 install -r checkpot/requirements.txt

CMD python3 checkpot/ci_automated_tests.py
