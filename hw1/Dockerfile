FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \ 
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt

RUN pip3 install -r /tmp/requirements.txt

RUN apt-get update \
    && apt-get install -y software-properties-common \
    && rm -rf /var/lib/apt/lists/* \
    && add-apt-repository universe \
    && apt update \
	&& apt-get install -y  graphviz \
	&& pip install pydot

WORKDIR /app

COPY . /app

CMD ["./test.sh"]
