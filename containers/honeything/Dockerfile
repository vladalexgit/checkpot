FROM python:2.7

RUN git clone https://github.com/omererdem/honeything.git

RUN pip install setuptools pycurl

RUN cd honeything && python setup.py install #because the script uses ./ internally

CMD service honeything start

#FIXME not working...