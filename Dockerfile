FROM python

RUN mkdir checkpot
COPY ./ checkpot/

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y nmap

RUN pip install -r checkpot/requirements.txt

CMD python checkpot/ci_automated_tests.py
