FROM python:3-alpine
# FROM python:2-alpine
MAINTAINER Thanh Tong "thtong@gmail.com"
RUN pip install plotly
RUN pip install --pre scapy[basic]
RUN apk add p0f --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing
RUN pip install p0f
COPY . /app
WORKDIR /app
EXPOSE 443 21
CMD python ./honeypot.py