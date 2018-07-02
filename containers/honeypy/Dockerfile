FROM python:2.7

RUN git clone https://github.com/foospidy/honeypy.git

RUN pip install -r honeypy/requirements.txt

CMD (echo "start" && cat) | python honeypy/Honey.py

# TODO bind remaining ports
