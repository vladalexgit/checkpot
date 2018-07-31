FROM python:2.7

RUN git clone https://www.github.com/phype/telnet-iot-honeypot.git

RUN pip install -r telnet-iot-honeypot/requirements.txt

# it references files using ./ must cd to run it
CMD cd telnet-iot-honeypot && python honeypot.py

# FIXME port still not open