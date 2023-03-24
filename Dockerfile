FROM python:3.10-alpine

RUN apk add libmagic python3-dev libffi-dev gcc musl-dev libxml2-dev libxml2 libxslt-dev py3-lxml
RUN cp -r /usr/lib/python3.*/site-packages/lxml/ /usr/local/lib/python3.10/site-packages/
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENV FLASK_DEBUG=1
RUN flask reset_app
CMD flask run --host=0.0.0.0
EXPOSE 5000
