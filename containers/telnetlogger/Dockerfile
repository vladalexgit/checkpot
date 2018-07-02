FROM ubuntu

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y git build-essential

RUN git clone https://github.com/robertdavidgraham/telnetlogger.git

RUN cd telnetlogger && make

CMD telnetlogger/telnetlogger
