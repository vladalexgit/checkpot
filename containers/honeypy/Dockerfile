FROM python:2.7

RUN git clone https://github.com/foospidy/honeypy.git

RUN pip install -r honeypy/requirements.txt

CMD bash -c "python honeypy/Honey.py <<< start && /bin/bash"

# FIXME keep the console running and bind ports...