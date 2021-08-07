FROM python:2.7-alpine

RUN pip install flask 

COPY ./src /chal
WORKDIR /chal

EXPOSE 5000
CMD flask run --host=0.0.0.0




